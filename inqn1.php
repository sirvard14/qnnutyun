<?php
// --- Database connection ---
$DB_HOST = 'localhost';
$DB_NAME = 'catalog';
$DB_USER = 'root';
$DB_PASS = '';

$dsn = "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4";

try {
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch(PDOException $e){
    die("DB connection failed: ".htmlspecialchars($e->getMessage()));
}

// --- Session & helpers ---
session_start();

function is_logged_in(){ return !empty($_SESSION['user_id']); }
function current_user_id(){ return $_SESSION['user_id'] ?? null; }
function csrf_token(){
    if(empty($_SESSION['csrf_token'])) $_SESSION['csrf_token']=bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}
function check_csrf($token){ return hash_equals($_SESSION['csrf_token']??'',$token??''); }
function e($s){ return htmlspecialchars($s, ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }

// --- Handle actions ---
$errors = [];
$action = $_GET['action'] ?? 'home';

// Logout
if($action==='logout'){
    session_unset();
    session_destroy();
    header('Location: catalog.php'); exit;
}

// Register
if($action==='register' && $_SERVER['REQUEST_METHOD']==='POST'){
    if(!check_csrf($_POST['csrf']??'')) $errors[]='Invalid CSRF token';
    $username=trim($_POST['username']??'');
    $email=filter_var($_POST['email']??'',FILTER_VALIDATE_EMAIL);
    $password=$_POST['password']??'';
    $password2=$_POST['password2']??'';
    if($username==='') $errors[]='Username required';
    if(!$email) $errors[]='Valid email required';
    if(strlen($password)<6) $errors[]='Password min 6 chars';
    if($password!==$password2) $errors[]='Passwords do not match';
    if(empty($errors)){
        $hash=password_hash($password,PASSWORD_DEFAULT);
        try{
            $stmt=$pdo->prepare('INSERT INTO users(username,email,password_hash) VALUES(?,?,?)');
            $stmt->execute([$username,$email,$hash]);
            $_SESSION['user_id']=$pdo->lastInsertId();
            header('Location: catalog.php'); exit;
        }catch(PDOException $e){
            if($e->errorInfo[1]===1062) $errors[]='Username or email taken';
            else $errors[]='DB error: '.e($e->getMessage());
        }
    }
}

// Login
if($action==='login' && $_SERVER['REQUEST_METHOD']==='POST'){
    if(!check_csrf($_POST['csrf']??'')) $errors[]='Invalid CSRF token';
    $username=trim($_POST['username']??'');
    $password=$_POST['password']??'';
    if($username===''||$password==='') $errors[]='Enter username & password';
    if(empty($errors)){
        $stmt=$pdo->prepare('SELECT id,password_hash FROM users WHERE username=? LIMIT 1');
        $stmt->execute([$username]);
        $user=$stmt->fetch();
        if($user && password_verify($password,$user['password_hash'])){
            $_SESSION['user_id']=$user['id'];
            header('Location: catalog.php'); exit;
        }else $errors[]='Incorrect credentials';
    }
}

// Add product
if($action==='add_product' && is_logged_in() && $_SERVER['REQUEST_METHOD']==='POST'){
    if(!check_csrf($_POST['csrf']??'')) $errors[]='Invalid CSRF token';
    $title=trim($_POST['title']??'');
    $desc=trim($_POST['description']??'');
    $price=$_POST['price']??0;
    if($title==='') $errors[]='Title required';
    if($desc==='') $errors[]='Description required';
    if(!is_numeric($price)) $errors[]='Price numeric';
    $image=null;
    if(!empty($_FILES['image']) && $_FILES['image']['error']!==UPLOAD_ERR_NO_FILE){
        $f=$_FILES['image'];
        $allowed=['image/jpeg'=>'jpg','image/png'=>'png','image/gif'=>'gif'];
        $ext=$allowed[mime_content_type($f['tmp_name'])]??null;
        if(!$ext) $errors[]='Only JPG/PNG/GIF allowed';
        if(empty($errors)){
            $image=bin2hex(random_bytes(8)).'.'.$ext;
            if(!is_dir('uploads')) mkdir('uploads',0755,true);
            move_uploaded_file($f['tmp_name'], __DIR__.'/uploads/'.$image);
        }
    }
    if(empty($errors)){
        $stmt=$pdo->prepare('INSERT INTO products(user_id,title,description,price,image) VALUES(?,?,?,?,?)');
        $stmt->execute([current_user_id(),$title,$desc,$price,$image]);
        header('Location: catalog.php'); exit;
    }
}

// --- HTML ---
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Catalog</title></head>
<body>
<header>
<h1>Catalog</h1>
<nav>
<?php if(is_logged_in()): ?>
<a href="?action=add_product">Add Product</a> | <a href="?action=logout">Logout</a>
<?php else: ?>
<a href="?action=login">Login</a> | <a href="?action=register">Register</a>
<?php endif; ?>
</nav>
<hr>
</header>
<main>

<?php if($errors): ?>
<div style="color:red"><ul><?php foreach($errors as $er): ?><li><?=e($er)?></li><?php endforeach;?></ul></div>
<?php endif; ?>

<?php if($action==='register'): ?>
<h2>Register</h2>
<form method="post">
<input type="hidden" name="csrf" value="<?=e(csrf_token())?>">
<label>Username<br><input name="username" value="<?=e($_POST['username']??'')?>"></label><br>
<label>Email<br><input name="email" value="<?=e($_POST['email']??'')?>"></label><br>
<label>Password<br><input type="password" name="password"></label><br>
<label>Repeat Password<br><input type="password" name="password2"></label><br>
<button type="submit">Register</button>
</form>

<?php elseif($action==='login'): ?>
<h2>Login</h2>
<form method="post">
<input type="hidden" name="csrf" value="<?=e(csrf_token())?>">
<label>Username<br><input name="username" value="<?=e($_POST['username']??'')?>"></label><br>
<label>Password<br><input type="password" name="password"></label><br>
<button type="submit">Login</button>
</form>

<?php elseif($action==='add_product' && is_logged_in()): ?>
<h2>Add Product</h2>
<form method="post" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="<?=e(csrf_token())?>">
<label>Title<br><input name="title" value="<?=e($_POST['title']??'')?>"></label><br>
<label>Description<br><textarea name="description"><?=e($_POST['description']??'')?></textarea></label><br>
<label>Price<br><input name="price" value="<?=e($_POST['price']??'0.00')?>"></label><br>
<label>Image<br><input type="file" name="image"></label><br>
<button type="submit">Add</button>
</form>

<?php endif; ?>

<h2>Products</h2>
<?php
$stmt=$pdo->query('SELECT p.*, u.username FROM products p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC');
$products=$stmt->fetchAll();
if(!$products) echo "<p>No products yet.</p>";
else foreach($products as $p):
?>
<article>
<h3><?=e($p['title'])?></h3>
<?php if($p['image']): ?><img src="uploads/<?=e($p['image'])?>" style="max-width:200px"><?php endif;?>
<p><?=nl2br(e($p['description']))?></p>
<p>Price: <?=e($p['price'])?></p>
<p>Added by: <?=e($p['username'])?> on <?=e($p['created_at'])?></p>
<hr>
</article>
<?php endforeach; ?>

</main>
</body>
</html>
