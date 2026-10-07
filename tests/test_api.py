import pytest
from httpx import ASGITransport, AsyncClient

from ast_sentinel.main import app


@pytest.fixture
def transport():
    return ASGITransport(app=app)


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_returns_ok(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_reports_version(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
        assert resp.json()["version"] == "0.1.0"

    @pytest.mark.asyncio
    async def test_rules_loaded(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
        assert resp.json()["rules_loaded"] >= 6


class TestScanSourceEndpoint:
    @pytest.mark.asyncio
    async def test_detects_vulnerability(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/scan/source", json={
                "source": "PASSWORD = 'secret123'",
                "filename": "test.py",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["result"]["summary"]["total_findings"] >= 1
        assert data["duration_ms"] >= 0

    @pytest.mark.asyncio
    async def test_clean_code_no_findings(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/scan/source", json={
                "source": "x = 1\nprint(x)",
                "filename": "clean.py",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["result"]["summary"]["total_findings"] == 0

    @pytest.mark.asyncio
    async def test_returns_scan_id(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/scan/source", json={
                "source": "x = 1",
                "filename": "test.py",
            })
        data = resp.json()
        assert len(data["result"]["scan_id"]) > 0

    @pytest.mark.asyncio
    async def test_returns_risk_score(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/scan/source", json={
                "source": "PASSWORD = 'secret123'",
                "filename": "test.py",
            })
        data = resp.json()
        assert data["result"]["risk_score"] is not None
        assert data["result"]["risk_score"] >= 0


class TestScanDirectoryEndpoint:
    @pytest.mark.asyncio
    async def test_nonexistent_path_returns_404(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/scan/directory", json={
                "directory_path": "/nonexistent/path/xyz",
            })
        assert resp.status_code == 404


class TestReportEndpoints:
    @pytest.mark.asyncio
    async def test_scan_then_retrieve_json(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Scan first
            scan_resp = await client.post("/api/v1/scan/source", json={
                "source": "PASSWORD = 'abc'",
                "filename": "t.py",
            })
            scan_id = scan_resp.json()["result"]["scan_id"]

            # Retrieve JSON report
            report_resp = await client.get(f"/api/v1/report/{scan_id}")
        assert report_resp.status_code == 200
        assert report_resp.json()["scan_id"] == scan_id

    @pytest.mark.asyncio
    async def test_scan_then_retrieve_html(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            scan_resp = await client.post("/api/v1/scan/source", json={
                "source": "PASSWORD = 'abc'",
                "filename": "t.py",
            })
            scan_id = scan_resp.json()["result"]["scan_id"]

            html_resp = await client.get(f"/api/v1/report/{scan_id}/html")
        assert html_resp.status_code == 200
        assert "AST-Sentinel" in html_resp.text

    @pytest.mark.asyncio
    async def test_missing_scan_id_returns_404(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/report/nonexistent-id")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_missing_scan_id_html_returns_404(self, transport):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/report/nonexistent-id/html")
        assert resp.status_code == 404
