from __future__ import annotations

import asyncio

import pytest
from httpx import AsyncClient

from acip.types import Role

SAMPLE_LOG = "\n".join(
    [
        "Mar 10 03:11:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.55 port 44120 ssh2",
        "Mar 10 03:11:05 web01 sshd[1235]: Failed password for invalid user root from 203.0.113.55 port 44122 ssh2",
        "Mar 10 03:11:09 web01 sshd[1236]: Failed password for invalid user test from 203.0.113.55 port 44124 ssh2",
        "Mar 10 03:11:12 web01 sshd[1237]: Failed password for deploy from 203.0.113.55 port 44126 ssh2",
        "Mar 10 03:11:15 web01 sshd[1238]: Failed password for deploy from 203.0.113.55 port 44128 ssh2",
        "Mar 10 03:11:20 web01 sshd[1239]: Accepted password for deploy from 203.0.113.55 port 44130 ssh2",
        "Mar 10 03:11:25 web01 sudo[1245]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "",
    ]
)


@pytest.mark.asyncio
async def test_evidence_graph_and_timeline_pipeline(
    client: AsyncClient, auth_headers: dict[Role, dict[str, str]]
) -> None:
    # 1. Create investigation
    resp_create = await client.post(
        "/api/v1/investigations",
        json={
            "title": "Evidence Graph Pipeline Verification",
            "target_type": "log",
            "target_value": "auth.log",
        },
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_create.status_code == 201
    inv_id = resp_create.json()["id"]

    # 2. Upload log artifact
    files = {"file": ("auth.log", SAMPLE_LOG.encode("utf-8"), "text/plain")}
    resp_upload = await client.post(
        f"/api/v1/investigations/{inv_id}/artifacts",
        files=files,
        data={"kind": "linux_auth_log"},
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_upload.status_code == 201

    # 3. Start investigation
    resp_start = await client.post(
        f"/api/v1/investigations/{inv_id}/start",
        headers=auth_headers[Role.INVESTIGATOR],
    )
    assert resp_start.status_code == 200

    # 4. Wait for investigation to finish
    detail: dict | None = None
    for _ in range(50):
        await asyncio.sleep(0.1)
        resp_detail = await client.get(
            f"/api/v1/investigations/{inv_id}", headers=auth_headers[Role.VIEWER]
        )
        assert resp_detail.status_code == 200
        detail = resp_detail.json()
        if detail["investigation"]["status"] in {"completed", "partial", "failed"}:
            break

    assert detail is not None
    assert detail["investigation"]["status"] == "completed"
    findings = detail["findings"]
    assert len(findings) >= 1

    # 5. Query Full Evidence Graph
    resp_graph = await client.get(
        f"/api/v1/investigations/{inv_id}/graph",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_graph.status_code == 200
    graph_data = resp_graph.json()
    assert graph_data["investigation_id"] == inv_id
    assert len(graph_data["entities"]) >= 3
    assert len(graph_data["edges"]) >= 2
    assert not graph_data["truncated"]

    # Invariant G0 check on edges: every edge must have a valid evidence_id
    for edge in graph_data["edges"]:
        assert edge["evidence_id"] is not None
        assert edge["relation"] in {
            "AUTHENTICATED_TO",
            "FAILED_AUTH_TO",
            "CONNECTED_FROM",
            "ASSOCIATED_WITH",
            "CONNECTED_TO_PORT",
        }

    entity_values = {e["value_normalized"] for e in graph_data["entities"]}
    assert "deploy" in entity_values
    assert "203.0.113.55" in entity_values

    # 6. Query Entities endpoint with filters
    resp_entities = await client.get(
        f"/api/v1/investigations/{inv_id}/entities?type=user",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_entities.status_code == 200
    user_entities = resp_entities.json()
    assert all(e["type"] == "user" for e in user_entities)
    assert any(e["value_normalized"] == "deploy" for e in user_entities)

    resp_search = await client.get(
        f"/api/v1/investigations/{inv_id}/entities?q=deploy",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_search.status_code == 200
    search_res = resp_search.json()
    assert len(search_res) >= 1
    assert search_res[0]["value_normalized"] == "deploy"
    deploy_entity_id = search_res[0]["id"]

    # 7. Neighborhood traversal rooted at deploy entity
    resp_neigh = await client.get(
        f"/api/v1/investigations/{inv_id}/graph?entity={deploy_entity_id}&depth=1",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_neigh.status_code == 200
    neigh_data = resp_neigh.json()
    assert any(e["id"] == deploy_entity_id for e in neigh_data["entities"])
    assert len(neigh_data["edges"]) >= 1

    # 8. Query Timeline endpoint
    resp_timeline = await client.get(
        f"/api/v1/investigations/{inv_id}/timeline",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_timeline.status_code == 200
    timeline_data = resp_timeline.json()
    assert timeline_data["total"] >= 5
    assert len(timeline_data["events"]) == timeline_data["total"]
    # Check that events carry source_tool and entities
    first_ev = timeline_data["events"][0]
    assert first_ev["source_tool"] == "linux_auth_log_parser"
    assert len(first_ev["entities"]) > 0

    # 9. Query Finding Subgraph for finding citing evidence with graph relations
    finding = next(
        (f for f in findings if f.get("detection_rule") and "correlation" in f["detection_rule"]),
        findings[-1],
    )
    finding_id = finding["id"]
    resp_subgraph = await client.get(
        f"/api/v1/investigations/{inv_id}/findings/{finding_id}/subgraph",
        headers=auth_headers[Role.VIEWER],
    )
    assert resp_subgraph.status_code == 200
    subgraph_data = resp_subgraph.json()
    assert subgraph_data["investigation_id"] == inv_id
    # Citations in finding point to evidence which produces edges/nodes
    assert len(subgraph_data["entities"]) >= 1
    assert len(subgraph_data["edges"]) >= 1
