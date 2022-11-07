<?php

namespace App\Controllers;

use App\Models\AppUser;


//! A adapter selon les différentes variables présentes


class UserController extends CoreController {


    /**
     * Méthode qui affiche le formulaire de connexion
     *
     * @return void
     */
    public function loginFormAction()
    {

        // Si on est connecté, on n'a rien à faire sur cette page, on redirige vers la d'accueil.
        if(isset($_SESSION['connectedUser'])) {

            // On ajoute un message d'erreur
            $this->addError("Vous etes déjà connecté, c'est pas gentil !");

            $this->redirect('main-home');

        } else{
            // on affiche la vue contenant le formulaire de connexion
            $this->show('main/login');

        }
    }


    /**
     * Méthode de traitement du formulaire de connexion
     *
     * @return void
     */
    public function connectAction()
    {

        // On récupère les infos du formulaire
        $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
        $password = filter_input(INPUT_POST, 'password');
        
        // On vérifie les données tapées par l'utilisateur
        if(empty($email) || empty($password)) {
            echo "Les champs doivent etre remplis";
            exit;
        }

        // On va chercher dans la BDD un utilisateur portant l'email demandé.
        $user = AppUser::findByEmail($email);

        // Si  aucun utilisateur n'a été trouvé, $user contient false
        if($user === false) {
            
            // On crée une "boite à messages d'erreur" dans la session. Et on range chaque erreur trouvée dedans
            $this->addError("Utilisateur non trouvé");

            // on redirige l'utilisateur vers la page de connexion
            $this->redirect('user-loginform');
             

        } else {
            // On vérifie que le mot de passe de l'utilisateur en BDD correspond au mot de passe tapé dans le formulaire
            if(password_verify($password, $user->getPassword())) {

                // Dans notre projet, on détermine qu'un utilisateur connecté est un utilisateur qui possède une entrée "connectedUser" dans sa session.

                $_SESSION['connectedUser'] = $user;


                // On stocke un message de succès dans la session
                $_SESSION['successMessages'][] = "Connexion réussie !";


                // Une fois connecté, on redirige l'utilisateur vers la page d'accueil
                $this->redirect('main-home');
                

            } else {
                $this->addError("Mot de passe incorrect");

                // on redirige l'utilisateur vers la page de connexion
                $this->redirect('user-loginform');
            }
        }

       
    }

    public function logoutAction()
    {
        // On déconnecte l'utilisateur en supprimant l'entrée "connectedUser" de sa session
        unset($_SESSION['connectedUser']);

        // On ajoute un message de succès
        $_SESSION['successMessages'][] = "Déconnexion effective !";

        // On redirige vers la page d'accueil
        $this->redirect('main-home');
    }

    /**
     * Affiche la liste des utilisateurs
     *
     * @return void
     */
    public function listAction()
    {

        // On bloque l'accès aux personnes qui n'ont pas le role admin
        // $this->checkAuthorization(['admin']);

        // On récupère la liste des utilisateurs
        $users = AppUser::findAll();
        
        $this->show('user/list', [
            'users' => $users
        ]);
    }

    /**
     * Affiche le formulaire d'ajout 
     *
     * @return void
     */
    public function addAction()
    {


        // On bloque l'accès aux personnes qui n'ont pas le role admin
        // $this->checkAuthorization(['admin']);


        // Pour se protéger des attaques CSRF, on doit générer une clé aléatoire qu'on va envoyer au formulaire.
        $token = $this->generateCSRFToken();

     
        $this->show('user/add', [
            'token' => $token,
        ]);
    }

    /**
     * Traitement des données du formulaire d'ajout
     *
     * @return void
     */
    public function createAction()
    {

        // $this->checkAuthorization(['admin']);


        // On récupère les différents champs
        $lastname = filter_input(INPUT_POST, 'lastname');
        $firstname = filter_input(INPUT_POST, 'firstname');
        $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
        $password = filter_input(INPUT_POST, 'password');
        $role = filter_input(INPUT_POST, 'role');
        $status = filter_input(INPUT_POST, 'status');


        // On vérifie si l'email est correct
        if($email === false) {
            $this->addError('Vous devez entrer un email correct');
        }

        // On vérifie que tous les champs sont remplis
        if(empty($lastname) || empty($firstname) || empty($email) || empty($password) || empty($role) || empty($status)) {
            $this->addError('Tous les champs doivent etre remplis !');
        }

        // On vérifie que le role et l'admin sont corrects
        if($role !== 'admin' && $role !== 'catalog-manager') {
            $this->addError("Le role n'est pas correct !");
        }
        if($status !== '0' && $status !== '1') {
            $this->addError("Le statut n'est pas correct !");
        }

        // Si un seul des champs est incorrect, on a ajouté une erreur à la liste des erreurs. Donc l'entrée errorMessages de la session n'est pas vide.
        // On a délégué l'opération de vérification des erreurs à une méthode dédiée hasErrors
        if($this->hasErrors()) {
            // Si on a des erreurs, on redirige vers le formulaire
            $this->redirect('user-add');
        }


        // On se crée un objet AppUser
        $newUser = new AppUser();

  
        // On remplit les propriétés
        $newUser->setEmail($email);
        $newUser->setFirstname($firstname);
        $newUser->setLastname($lastname);
        $newUser->setRole($role);
        $newUser->setStatus($status);

       
        // Avant d'ajouter le mot de passe, on procède à son hachage
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // On remplit la propriété avec le mot de passe haché
        $newUser->setPassword($hashedPassword);
        
        // On sauvegarde l'utilisateur en BDD
        if($newUser->save()) {

            $_SESSION['successMessages'][] = "Utilisateur bien créé !";
            $this->redirect('user-list');
        }

        
    }



}