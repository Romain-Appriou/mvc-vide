<?php 

namespace App\Controllers;

abstract class CoreController {

    public $router;

    /** Le constructeur du CoreCOntroller est automatiquement exécuté quand on instancie n'importe lequel de ses enfants. Donc sur toutes les pages du projet, ce constructeur sera exécuté. 
     * On pourra donc y mettre n'importe quel code qui doit etre exécuté sur toutes les pages, ici notre ACL !
    */
    public function __construct($routeName, $router)
    {
    // On range le router reçu d'altodispatcher dans la propriété $this->router. Ainsi, dans tous nos controllers on pourra accéder à cette propriété router et utilise ses outils comme generate
    $this->router = $router;

    $acl = [
        
       //! à redéfinir 'main-home' => ['admin', 'catalog-manager']
    ];

    // On vérifie si la route actuelle fait partie des routes protégées (donc si c'est une des clés du tableau)
    if(isset($acl[$routeName])) {

        // On récupère dans le tableau la liste des roles autorisés
        $roles = $acl[$routeName];
    
        // On appele la méthode checkAuthorization qui vérifie que l'utilisateur courant possède bien les roles autorisés
        $this->checkAuthorization($roles);

                                }

}

    /**
     * Méthode permettant d'afficher du code HTML en se basant sur les views
     *
     * @param string $viewName Nom du fichier de vue
     * @param array $viewData Tableau des données à transmettre aux vues
     * @return void
     */
    protected function show(string $viewName, $viewData = [])
    {
        // On globalise $router car on ne sait pas faire mieux pour l'instant
        // global $router;

        // On utilise maintenant le router stockée en propriété du coreController 

        $router = $this->router;

        // Comme $viewData est déclarée comme paramètre de la méthode show()
        // les vues y ont accès
        // ici une valeur dont on a besoin sur TOUTES les vues
        // donc on la définit dans show()
        $viewData['currentPage'] = $viewName;

        // définir l'url absolue pour nos assets
        $viewData['assetsBaseUri'] = $_SERVER['BASE_URI'] . 'assets/';
        // définir l'url absolue pour la racine du site
        // /!\ != racine projet, ici on parle du répertoire public/
        $viewData['baseUri'] = $_SERVER['BASE_URI'];
    
        // On veut désormais accéder aux données de $viewData, mais sans accéder au tableau
        // La fonction extract permet de créer une variable pour chaque élément du tableau passé en argument
        extract($viewData);
        // => la variable $currentPage existe désormais, et sa valeur est $viewName
        // => la variable $assetsBaseUri existe désormais, et sa valeur est $_SERVER['BASE_URI'] . '/assets/'
        // => la variable $baseUri existe désormais, et sa valeur est $_SERVER['BASE_URI']
        // => il en va de même pour chaque élément du tableau
        
        // $viewData est disponible dans chaque fichier de vue
        require_once __DIR__ . '/../views/layout/header.tpl.php';
        require_once __DIR__ . '/../views/' . $viewName . '.tpl.php';
        require_once __DIR__ . '/../views/layout/footer.tpl.php';
    }

 /**
     * Méthode permettant de rediriger vers n'importe quelle page de notre application
     *
     * @param string $routeName
     * @return void
     */
    protected function redirect($routeName)
    {
        // On utilise le mot clé global pour avoir accès à la variable $router contenant notre instance d'altorouter
        // global $router;
        // On génère l'url vers la page ciblée
        $url = $this->router->generate($routeName);
        // On la transmet à header
        header('Location: ' . $url);
        // On coupe l'exécution de cette page
        exit;
    }

    /**
     * Méthode qui vérifie que l'utilisateur actuellement connecté possède un des roles donnés en paramètre
     *
     * @param array $roles Contient la liste des roles autorisés
     * @return void
     */
    public function checkAuthorization($roles)
    {
        // On vérifie si  l'utilisateur est connecté
        if(isset($_SESSION['connectedUser'])) {

            // S'il est connecté, on récupère l'objet AppUser de la session
            $currentUser = $_SESSION['connectedUser'];

            // On récupère le role de l'utilisateur (getter getRole)
            $userRole = $currentUser->getRole();

            // En suite on vérifie si le role de l'utilisateur fait partie du tableau de roles reçu en paramètre.
            // https://www.php.net/manual/en/function.in-array.php
            if(in_array($userRole,$roles)) {
                // Si oui, on retourne true
                return true;
            } else {
                
                // On indique au navigateur que la page demandée n'est pas accessible à cet utilisateur
                http_response_code(403);

                // On affiche le template d'erreur 403
                $this->show('error/err403');

                // Pour éviter que PHP n'affiche la page censée etre affichée normalement, on bloque l'exécution de PHP pour tout arreter.
                exit;

            }
            
            
        } else {

            // On ajoute un message d'erreur
            $this->addError("Vous devez vous connecter pour accéder à cette page !");


            // Sinon, on le redirige vers la page de connexion

            $this->redirect('user-loginform');

        }

    }

    /**
     * Ajoute un message d'erreur dans la liste des erreurs en session
     *
     * @param string $message Message d'erreur à ajouter.
     * @return void
     */
    public function addError($message)
    {
        // On ajoute le message d'erreur dans la boite d'erreurs de la session
        $_SESSION['errorMessages'][] = $message;
    }

    /**
     * Indique si on a des erreurs dans la session
     *
     * @return boolean
     */
    public function hasErrors()
    {
        // On teste grace à une condition entre parenthèses si la boite à erreurs est vide. Si elle n'est pas vide, la fonction empty va renvoyer true. Et on renvoie cette information avec return.
        return (!empty($_SESSION['errorMessages']));
    }

}