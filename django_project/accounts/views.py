from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout 
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from social_django.utils import load_strategy, load_backend
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import MissingBackend, AuthTokenError, AuthForbidden
from django.conf import settings
import json
from rest_framework.authtoken.models import Token
from social_core.backends.google import GoogleOAuth2
from social_core.exceptions import AuthFailed


def home(request):
    """Vista que renderiza la página principal"""
    return render(request, 'accounts/home.html')


def signup(request):
    """
    Vista para registrar nuevos usuarios.
    Si el método es POST, procesa el formulario de registro.
    Si es válido, crea el usuario, lo loguea y redirecciona a home.
    Si es GET, muestra el formulario de registro.
    """
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'accounts/signup.html', {'form': form})


@login_required
def profile(request):
    """
    Vista protegida que muestra el perfil del usuario.
    Requiere que el usuario esté autenticado.
    """
    return render(request, 'accounts/profile.html')


def logout_view(request):
    """
    Vista para cerrar la sesión del usuario.
    Desloguea al usuario y redirecciona a la página de login.
    Funciona tanto para usuarios registrados tradicionalmente
    como para usuarios autenticados con Google.
    """
    logout(request)
    return redirect('login')


@api_view(['POST'])  # Decorador que indica que esta vista solo acepta peticiones POST
@permission_classes([AllowAny])  # Permite que cualquier usuario (autenticado o no) acceda a esta vista
def google_auth(request):
    """
    Vista para manejar la autenticación con Google desde React.
    Espera recibir el token de acceso de Google en el cuerpo de la solicitud.
    
    El flujo es el siguiente:
    1. El frontend (React) obtiene un token de acceso de Google
    2. Envía ese token a esta vista mediante una petición POST
    3. La vista valida el token con Google y obtiene los datos del usuario
    4. Si es válido, crea/obtiene un usuario en Django y genera un token de autenticación
    5. Devuelve el token y los datos del usuario al frontend
    
    Si el usuario no existe en la base de datos, se crea automáticamente usando
    los datos proporcionados por Google (email, nombre, etc).
    """
    try:
        # Obtener el token de acceso de Google del cuerpo de la solicitud
        # Este token lo envía el frontend después de que el usuario se autentica con Google
        access_token = request.data.get('access_token')
        
        # Validar que se haya proporcionado un token
        if not access_token:
            return Response({'error': 'Token de acceso no proporcionado'}, status=400)
        
        # Configurar la estrategia y el backend de autenticación
        # load_strategy() inicializa el entorno de autenticación de la libreria social
        # GoogleOAuth2 es el backend específico para Google
        strategy = load_strategy(request)
        backend = GoogleOAuth2(strategy=strategy)
        
        try:
            # do_auth() valida el token con Google y obtiene/crea el usuario en Django
            # Si el token es válido, retorna un objeto User de Django
            # Si el usuario no existe, lo crea automáticamente con los datos de Google
            user = backend.do_auth(access_token)
            
            if user:
                # Si se obtuvo un usuario válido (existente o recién creado), 
                # generamos un token de autenticación
                # get_or_create retorna una tupla (objeto, created)
                # El _ ignora el booleano created que no necesitamos
                token, _ = Token.objects.get_or_create(user=user)
                
                # Devolver el token y los datos básicos del usuario
                return Response({
                    'token': token.key,  # Token que usará el frontend para futuras peticiones
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                    }
                })
            else:
                # Si no se pudo obtener un usuario, devolver error
                return Response({'error': 'No se pudo autenticar con Google'}, status=400)
                
        except AuthFailed as e:
            # Error específico de autenticación (token inválido, expirado, etc)
            return Response({'error': str(e)}, status=400)
            
    except Exception as e:
        # Captura cualquier otro error no esperado
        print(e)  # Log del error para debugging
        return Response({'error': 'Error en la autenticación'}, status=500)
