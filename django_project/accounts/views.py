from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout 
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required


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
