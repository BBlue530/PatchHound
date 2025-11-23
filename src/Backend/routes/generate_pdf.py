from flask import request, jsonify, send_file, Blueprint
from file_system.pdf_generator import summary_to_pdf
from utils.jwt_path import decode_jwt_path_to_resources
from database.validate_token import validate_token

pdf_bp = Blueprint("pdf", __name__)

@pdf_bp.route('/v1/generate-pdf', methods=['GET'])
def generate_pdf():
    
    token_key = request.args.get("token")
    if not token_key:
        return jsonify({"error": "Token missing"}), 401
    
    audit_trail = False

    response, valid_token = validate_token(audit_trail, token_key)
    if valid_token == False:
        return jsonify({"error": f"{response}"}), 401
    organization = response

    path_to_resources_token = request.args.get("path_to_resources_token")
    if not path_to_resources_token:
        return jsonify({"error": "path_to_resources_token missing"}), 404
    organization_decoded, current_repo_decoded, timestamp_decoded, valid = decode_jwt_path_to_resources(path_to_resources_token, organization)
    
    if valid == True:
        pdf_filename_path = summary_to_pdf(organization_decoded, current_repo_decoded, timestamp_decoded)
        return send_file(pdf_filename_path, mimetype="application/pdf", as_attachment=True) 
    else:
        return jsonify({"error": "invalid jwt token"}), 404