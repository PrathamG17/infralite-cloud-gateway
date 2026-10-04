import requests
import pytest
import uuid
import os

BASE_URL = "http://localhost:8080"  
ADMIN_PASSWORD = os.environ.get("INFRALITE_TEST_ADMIN_PASSWORD")
VIEWER_PASSWORD = os.environ.get("INFRALITE_TEST_VIEWER_PASSWORD")

@pytest.fixture(scope="session")
def auth_headers():
    assert ADMIN_PASSWORD, "Set INFRALITE_TEST_ADMIN_PASSWORD for integration tests"
    response = requests.post(
        f"{BASE_URL}/login",
        json={"username": "admin", "password": ADMIN_PASSWORD},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}

def test_hello(auth_headers):
    r = requests.get(f"{BASE_URL}/hello", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["message"] == "Hello World"

def test_page(auth_headers):
    r = requests.get(f"{BASE_URL}/page", headers=auth_headers)
    assert r.status_code == 200
    assert "<h1>Welcome!" in r.text

def test_data(auth_headers):
    r = requests.get(f"{BASE_URL}/data", headers=auth_headers)
    assert r.status_code == 200
    assert "<value>42</value>" in r.text

def test_namaskar(auth_headers):
    r = requests.get(f"{BASE_URL}/namaskar", headers=auth_headers)
    assert r.status_code == 200
    assert "Namaskar!" in r.text

def test_json(auth_headers):
    r = requests.get(f"{BASE_URL}/json", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["message"] == "Hello JSON"

def test_submit(auth_headers):
    payload = {"data": "TestData"}
    r = requests.post(f"{BASE_URL}/submit", json=payload, headers=auth_headers)
    assert r.status_code == 200
    assert "TestData" in r.text

def test_not_found(auth_headers):
    r = requests.get(f"{BASE_URL}/doesnotexist", headers=auth_headers)
    assert r.status_code == 404

def test_submit_invalid(auth_headers):
    r = requests.post(f"{BASE_URL}/submit", json={}, headers=auth_headers)
    assert r.status_code == 400 or "error" in r.text.lower()

def test_route_management_crud(auth_headers):
    path = f"/pytest-{uuid.uuid4().hex}"
    created = requests.post(
        f"{BASE_URL}/api/routes",
        json={"method": "GET", "path": path, "status": 200, "responseBody": "created"},
        headers=auth_headers,
    )
    assert created.status_code == 201
    route_id = created.json()["routeId"]

    listed = requests.get(f"{BASE_URL}/api/routes", headers=auth_headers)
    assert listed.status_code == 200
    assert {"method": "GET", "path": path} in listed.json()

    updated = requests.put(
        f"{BASE_URL}/api/routes",
        json={"routeId": route_id, "method": "GET", "path": path,
              "status": 200, "responseBody": "updated"},
        headers=auth_headers,
    )
    assert updated.status_code == 200
    assert requests.get(f"{BASE_URL}{path}", headers=auth_headers).text == "updated"

    deleted = requests.delete(
        f"{BASE_URL}/api/routes", json={"routeId": route_id}, headers=auth_headers
    )
    assert deleted.status_code == 204

def test_route_management_rejects_viewer_writes():
    assert VIEWER_PASSWORD, "Bootstrap viewer and set INFRALITE_TEST_VIEWER_PASSWORD for integration tests"
    response = requests.post(
        f"{BASE_URL}/login",
        json={"username": "viewer1", "password": VIEWER_PASSWORD},
    )
    assert response.status_code == 200
    headers = {"Authorization": f"Bearer {response.json()['token']}"}
    result = requests.post(
        f"{BASE_URL}/api/routes",
        json={"method": "GET", "path": "/viewer-write", "status": 200, "responseBody": "x"},
        headers=headers,
    )
    assert result.status_code == 403
