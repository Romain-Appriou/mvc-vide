<?php 

require_once '../vendor/autoload.php';

session_start();


/* ------------
--- ROUTAGE ---
-------------*/

// création de l'objet router
// Cet objet va gérer les routes pour nous, et surtout il va
$router = new AltoRouter();

// le répertoire (après le nom de domaine) dans lequel on travaille est celui-ci
// Mais on pourrait travailler sans sous-répertoire
// Si il y a un sous-répertoire
if (array_key_exists('BASE_URI', $_SERVER)) {
    // Alors on définit le basePath d'AltoRouter
    $router->setBasePath($_SERVER['BASE_URI']);
    // ainsi, nos routes correspondront à l'URL, après la suite de sous-répertoire
} else { // sinon
    // On donne une valeur par défaut à $_SERVER['BASE_URI'] car c'est utilisé dans le CoreController
    $_SERVER['BASE_URI'] = '/';
}


$router->map(
    'GET',
    '/',
    [
        'method' => 'home',
        'controller' => 'MainController'
    ],
    'main-home'
);


/* -------------
--- DISPATCH ---
--------------*/

// On demande à AltoRouter de trouver une route qui correspond à l'URL courante
$match = $router->match();


// Ensuite, pour dispatcher le code dans la bonne méthode, du bon Controller
// On délègue à une librairie externe : https://packagist.org/packages/benoclock/alto-dispatcher
// 1er argument : la variable $match retournée par AltoRouter
// 2e argument : le "target" (controller & méthode) pour afficher la page 404
$dispatcher = new Dispatcher($match, 'ErrorController::err404');

// La méthode setControllersNamespace permet de définir un namespace commun à tous nos controllers. Ainsi on évite la répétition de ce namespace et donc les erreurs
$dispatcher->setControllersNamespace('App\Controllers');

// La méthode setControllersArguments permet d'envoyer au constructeur du controller des informations. Elles seront récupérées en paramètre du constructeur
$dispatcher->setControllersArguments($match['name'], $router);


// Une fois le "dispatcher" configuré, on lance le dispatch qui va exécuter la méthode du controller
$dispatcher->dispatch();
