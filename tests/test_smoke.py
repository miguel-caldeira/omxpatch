def test_app_boots_and_login_page(client):
    r = client.get("/login")
    assert r.status_code == 200 and b"OMX" in r.data
    assert client.get("/healthz").get_json()["status"] == "ok"


def test_login_and_dashboard(app):
    from tests.conftest import login_as
    c = login_as(app, "admin@alpha.example")
    r = c.get("/")
    assert r.status_code == 200 and "Painel executivo" in r.get_data(as_text=True)
