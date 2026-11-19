"""expired_tls_hotel_reservation's certificate is probed over HTTPS and alerted on."""

import re
from pathlib import Path

import yaml

VALUES = Path(__file__).resolve().parents[2] / "sregym/observer/prometheus/prometheus/values.yaml"
HOST = "hotel-reservation.local"


def _values():
    return yaml.safe_load(VALUES.read_text())


def _alerts(values):
    return {
        rule["alert"]: rule["expr"]
        for group in values["serverFiles"]["alerting_rules.yml"]["groups"]
        for rule in group["rules"]
        if "alert" in rule
    }


def test_probe_module_sends_the_tls_host_and_sni():
    module = _values()["prometheus-blackbox-exporter"]["config"]["modules"]["https_hotel_reservation"]["http"]
    assert module["headers"]["Host"] == HOST
    assert module["tls_config"]["server_name"] == HOST


def test_scrape_job_probes_the_ingress_controller_over_https():
    jobs = yaml.safe_load(_values()["extraScrapeConfigs"])
    job = next(j for j in jobs if j["job_name"] == "blackbox-tls-hotel-reservation")
    assert job["params"]["module"] == ["https_hotel_reservation"]
    assert job["static_configs"][0]["targets"] == ["https://ingress-nginx-controller.ingress-nginx/"]


def test_expiry_alert_and_http_probe_alert_stay_separate():
    alerts = _alerts(_values())
    assert "probe_ssl_earliest_cert_expiry" in alerts["TLSCertificateExpired"]
    assert 'deployment="ingress-nginx-controller"' in alerts["TLSCertificateExpired"]
    # The TLS probe also gets 404 whenever no TLS Ingress exists, so HTTPProbeFailure must not match it.
    ingress_regex = re.search(r'job=~"([^"]+)"', alerts["HTTPProbeFailure"]).group(1)
    assert not re.fullmatch(ingress_regex, "blackbox-tls-hotel-reservation")
