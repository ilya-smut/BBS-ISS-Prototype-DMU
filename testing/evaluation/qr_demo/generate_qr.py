import os
import json
import qrcode
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
import bbs_iss.interfaces.requests_api as api
from bbs_iss.utils.utils import gen_link_secret

def main():
    print("Setting up ecosystem...")
    registry = RegistryInstance()
    issuer = IssuerInstance()
    holder = HolderInstance()
    verifier = VerifierInstance()

    # 1. Register Issuer
    reg_req = issuer.register_issuer()
    reg_resp = registry.process_request(reg_req)
    issuer.process_request(reg_resp)

    issuer_name = "DMU-Registry"
    data = api.IssuerPublicData(issuer_name, issuer.public_key, "0"*10, 52, 7)
    holder.public_data_cache.update(issuer_name, data)

    # 2. Issue Baseline 10-Attribute Credential
    print("Issuing 10-attribute baseline credential...")
    attributes = api.IssuanceAttributes()
    # 9 revealed attributes
    for i in range(1, 10):
        attributes.append(f"attr_{i}", f"value_{i}", api.AttributeType.REVEALED)
    # 1 hidden attribute
    attributes.append("linkSecret", gen_link_secret(), api.AttributeType.HIDDEN)

    init_req = holder.issuance_request(
        issuer_name=issuer_name,
        attributes=attributes,
        cred_name="baseline-vc"
    )
    freshness = issuer.process_request(init_req)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    holder.process_request(forward_vc)

    # 3. Present Credential
    print("Generating Verifiable Presentation...")
    bulk_req = verifier.fetch_all_issuer_details()
    bulk_resp = registry.process_request(bulk_req)
    verifier.process_request(bulk_resp)

    # Verifier requests 5 attributes to be disclosed
    requested_attrs = ["attr_1", "attr_2", "attr_3", "attr_4", "attr_5"]
    vp_request = verifier.presentation_request(requested_attrs)

    vp_response = holder.present_credential(
        vp_request=vp_request,
        vc_name="baseline-vc",
        always_hidden_keys=["linkSecret"]
    )

    out_dir = os.path.dirname(os.path.abspath(__file__))

    # 4. Serialize VP Request to JSON and generate QR
    print("Serializing VP Request to JSON and generating QR Code...")
    vp_req_json = vp_request.to_json()
    req_json_bytes = len(vp_req_json.encode('utf-8'))
    print(f"VP Request JSON Size: {req_json_bytes} bytes")

    qr_req = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=4,
        border=4,
    )
    qr_req.add_data(vp_req_json)
    qr_req.make(fit=True)

    img_req = qr_req.make_image(fill_color="black", back_color="white")
    out_req_path = os.path.join(out_dir, "vp_request_qrcode.png")
    img_req.save(out_req_path)
    print(f"VP Request QR Code successfully saved to {out_req_path} (Version: {qr_req.version})")

    # 5. Serialize VP Response to JSON and generate QR
    print("Serializing VP Response to JSON and generating QR Code...")
    vp_json = vp_response.to_json()
    json_bytes = len(vp_json.encode('utf-8'))
    print(f"VP Response JSON Size: {json_bytes} bytes")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=4,
        border=4,
    )
    qr.add_data(vp_json)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    out_path = os.path.join(out_dir, "vp_qrcode.png")
    img.save(out_path)
    print(f"VP Response QR Code successfully saved to {out_path} (Version: {qr.version})")

if __name__ == "__main__":
    main()
