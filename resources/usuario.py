from flask_restful import Resource, reqparse
from models.usuario import UserModel

from flask_jwt_extended import create_access_token, jwt_required, get_raw_jwt
from werkzeug.security import safe_str_cmp
from blacklist import BLACKLIST
'''
class Usuarios(Resource):
    def get(self):
        return {'user': [user.json() for user in UserModel.query.all()]}
'''

atributos = reqparse.RequestParser()
atributos.add_argument('login', type=str, required=True, help="O campo login não pode ser nulo")
atributos.add_argument('senha', type=str, required=True, help="O campo senha não pode ser nulo")
atributos.add_argument('ativado', type=bool)

class User(Resource):
    # /usuarios/{user_id}
    def get(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            return user.json()
        return {'message': 'User not found.'}, 404

    @jwt_required
    def delete(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            try:
                user.delete_user()
            except:
                return {'message': 'erro interno ao tentar deletar'}, 500

            return {'message': 'User deleted.'}
        return {'message': 'User not found'}, 404

class UserRegister(Resource):
    # /cadastro

    def post(self):
        dados = atributos.parse_args()
        if UserModel.find_by_login(dados['login']):
            return {"message": "The login '{}' already exists.".format(dados['login'])}

        user = UserModel(**dados)
        user.ativado = False
        user.save_user()
        return {'message': 'User cread successfully!'}, 201

class UserLogin(Resource):

    @classmethod
    def post(cls):
        dados = atributos.parse_args()

        user = UserModel.find_by_login(dados['login'])

        if user and safe_str_cmp(user.senha, dados['senha']): #função para comparar senhas
            if user.ativado:
                token_de_acesso = create_access_token(identity=user.user_id) #função que cria um acesso para o usuario
                return {'acess_token': token_de_acesso}, 200
            return {'message': 'User not confirmed'}, 400
        return {'message': 'The username or password is incorrect.'}, 401

class UserLogout(Resource):

    @jwt_required
    def post(self):
        jwt_id = get_raw_jwt()['jti'] # jti = JWT Token Identif
        BLACKLIST.add(jwt_id)
        return {'message': 'Logged out successfully!'}, 200

class UserConfirm(Resource):

    @classmethod
    def get(cls, user_id):
        user = UserModel.find_user(user_id)

        if not user:
            return {'message': f'User id {user_id} not found.'}, 404

        user.ativado = True
        user.save_user()
        return {'message': f'User id {user_id} confirmed successfully.'}, 200
