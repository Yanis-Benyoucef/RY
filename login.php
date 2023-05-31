<?php
session_start();
require_once "config.php";

$username = $password = "";
$username_err = $password_err = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

  // Vérifier si le nom d'utilisateur est vide
  if (empty(trim($_POST["username"]))) {
    $username_err = "Veuillez entrer votre nom d'utilisateur.";
  } else {
    $username = trim($_POST["username"]);
  }

  // Vérifier si le mot de passe est vide
  if (empty(trim($_POST["password"]))) {
    $password_err = "Veuillez entrer votre mot de passe.";
  } else {
    $password = trim($_POST["password"]);
  }

  // Valider les informations d'identification
  if (empty($username_err) && empty($password_err)) {
    $sql = "SELECT id, username, password FROM users WHERE username = ?";

    if ($stmt = $conn->prepare($sql)) {
      $stmt->bind_param("s", $param_username);
      $param_username = $username;

      if ($stmt->execute()) {
        $stmt->store_result();

        if ($stmt->num_rows == 1) {
          $stmt->bind_result($id, $username, $hashed_password);
          if ($stmt->fetch()) {
            if (password_verify($password, $hashed_password)) {
              session_start();

              $_SESSION["loggedin"] = true;
              $_SESSION["id"] = $id;
              $_SESSION["username"] = $username;

              header("location: welcome.php");
            } else {
              $password_err = "Le mot de passe que vous avez entré n'est pas valide.";
            }
          }
        } else {
          $username_err = "Aucun compte trouvé avec ce nom d'utilisateur.";
        }
      } else {
        echo "Oops! Quelque chose s'est mal passé. Veuillez réessayer plus tard.";
      }
      $stmt->close();
    }
  }
  $conn->close();
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Connexion</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="container">
    <h2>Connexion</h2>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
      <div>
        <label>Nom d'utilisateur</label>
        <input type="text" name="username" value="<?php echo $username; ?>">
        <span class="error"><?php echo $username_err; ?></span>
      </div>
      <div>
        <label>Mot de passe</label>
        <input type="password" name="password">
        <span class="error"><?php echo $password_err; ?></span>
      </div>
      <div>
        <input type="submit" value="Se connecter">
      </div>
    </form>
  </div>
</body>
</html>