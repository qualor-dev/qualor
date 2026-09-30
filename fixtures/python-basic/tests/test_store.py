from app.store import Store


def test_classify():
    assert Store().classify(1, False) == "bronze"
