from weathercli import forecast


def test_forecast():
    assert "sunny" in forecast("Pune")
