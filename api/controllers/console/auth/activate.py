import base64
import secrets
from datetime import datetime

from flask_restful import Resource, reqparse

from controllers.console import api
from controllers.console.error import AlreadyActivateError
from extensions.ext_database import db
from libs.helper import email, str_len, supported_language, timezone
from libs.password import valid_password, hash_password
from models.account import AccountStatus, Tenant
from services.account_service import RegisterService


class ActivateCheckApi(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('workspace_id', type=str, required=True, nullable=False, location='args')
        parser.add_argument('email', type=email, required=True, nullable=False, location='args')
        parser.add_argument('token', type=str, required=True, nullable=False, location='args')
        args = parser.parse_args()

        account = RegisterService.get_account_if_token_valid(args['workspace_id'], args['email'], args['token'])

        tenant = db.session.query(Tenant).filter(
            Tenant.id == args['workspace_id'],
            Tenant.status == 'normal'
        ).first()

        return {'is_valid': account is not None, 'workspace_name': tenant.name}


class ActivateApi(Resource):
    def get(self):
        workspace_id = request.args.get('workspace_id')
        email = request.args.get('email')
        token = request.args.get('token')
        name = request.args.get('name')
        password = request.args.get('password')
        interface_language = request.args.get('interface_language')
        timezone = request.args.get('timezone')

        account = RegisterService.get_account_if_token_valid(workspace_id, email, token)
        if account is None:
            raise AlreadyActivateError()

        RegisterService.revoke_token(workspace_id, email, token)

        account.name = name

        salt = secrets.token_bytes(16)
        base64_salt = base64.b64encode(salt).decode()

        password_hashed = hash_password(password, salt)
        base64_password_hashed = base64.b64encode(password_hashed).decode()
        account.password = base64_password_hashed
        account.password_salt = base64_salt
        account.interface_language = interface_language
        account.timezone = timezone
        account.interface_theme = 'light'
        account.status = AccountStatus.ACTIVE.value
        account.initialized_at = datetime.utcnow()
        db.session.commit()

        return {'result': 'success'}


api.add_resource(ActivateCheckApi, '/activate/check')
api.add_resource(ActivateApi, '/activate')
