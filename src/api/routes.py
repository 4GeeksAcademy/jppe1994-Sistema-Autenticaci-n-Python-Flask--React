"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User,Owner
from api.utils import generate_sitemap, APIException
from flask_cors import CORS

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

#OWNER

@api.route('/owner', methods=['GET'])
def get_owners():
    all_owners= Owner.query.all()
    results = list(map(lambda owner: owner.serialize(), all_owners))
   
    return jsonify(results), 200

@api.route('/owner', methods=['POST'])
def create_owner():
    data = request.json
    required_fields = ["email", "password", "name"]
    for field in required_fields:
        if field not in data: return "The '" + field + "' cannot be empty", 400
    existing_owner = Owner.query.filter_by(email=data['email']).first()
    if existing_owner:
        return jsonify({"error": "Email already exists!"}), 409
    
    new_owner = Owner(email = data['email'], password = data['password'], name = data['name'])
    db.session.add(new_owner)
    db.session.commit()

    return jsonify({"message": "Owner created!"}), 200

@api.route("/owner/<int:owner_id>", methods=["GET"])
def get_owner(owner_id):
    owner = Owner.query.get(owner_id)
    return jsonify(owner.serialize()), 200

@api.route("/owner/<int:owner_id>", methods=["DELETE"])
def delete_owner(owner_id):
    owner = Owner.query.get(owner_id)

    db.session.delete(owner)
    db.session.commit()
    return jsonify({'message': 'Owner deleted'}), 200

@api.route("/owner/<int:owner_id>", methods=["PUT"])
def update_owner(owner_id):
    owner = Owner.query.get(owner_id)
    if not owner:
        return jsonify({"message": "Owner not found"}), 404
    
    data = request.json
    if "email" in data:
        owner.email = data["email"]
    if "password" in data:
        owner.password = data["password"]
    if "name" in data:
        owner.name = data["name"]

    db.session.commit()
    return jsonify(owner.serialize()), 200


@api.route('/login', methods=['POST'])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    owner = Owner.query.filter_by(email= email).first()
    if owner is None:
        return jsonify({"message":"Email not found"}), 401
    if password != owner.password:
        return jsonify({"message": "Wrong password"}), 401
    
    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token)

@api.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_owner = get_jwt_identity()
    return jsonify(logged_in_as=current_owner), 200 
