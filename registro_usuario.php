<?php


header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: *');
header('Content-Type: application/json');

$response = array();


$servername = "localhost";
$username = "root";
$password = "";
$dbname = "v3estore";


$conn = new mysqli($servername, $username, $password, $dbname);


if ($conn->connect_error) {
    $response['success'] = false;
    $response['message'] = "Error de conexión: " . $conn->connect_error;
    echo json_encode($response);
    exit();
}


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    
    $nombre = trim($_POST['nombre'] ?? '');
    $documento = trim($_POST['documento'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $fecha_nacimiento = $_POST['fecha_nacimiento'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmar_password = $_POST['confirmar_password'] ?? '';
    

    if (empty($nombre) || empty($documento) || empty($email) || empty($fecha_nacimiento) || empty($password)) {
        $response['success'] = false;
        $response['message'] = "Todos los campos son obligatorios";
        echo json_encode($response);
        exit();
    }
    
    if ($password !== $confirmar_password) {
        $response['success'] = false;
        $response['message'] = "Las contraseñas no coinciden";
        echo json_encode($response);
        exit();
    }
    
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response['success'] = false;
        $response['message'] = "El formato del email no es válido";
        echo json_encode($response);
        exit();
    }
    
    
    if (!preg_match('/^[a-zA-Z0-9]+$/', $documento)) {
        $response['success'] = false;
        $response['message'] = "El documento solo puede contener números y letras, sin espacios";
        echo json_encode($response);
        exit();
    }
    
    
    $fecha_nac = DateTime::createFromFormat('Y-m-d', $fecha_nacimiento);
    $hoy = new DateTime();
    $edad = $hoy->diff($fecha_nac)->y;
    
    if ($edad < 13) {
        $response['success'] = false;
        $response['message'] = "Debes tener al menos 13 años para registrarte";
        echo json_encode($response);
        exit();
    }
    
    $check_email = $conn->prepare("SELECT id FROM usuarios WHERE email = ?");
    $check_email->bind_param("s", $email);
    $check_email->execute();
    $check_email->store_result();
    
    if ($check_email->num_rows > 0) {
        $response['success'] = false;
        $response['message'] = "El email ya está registrado";
        $check_email->close();
        echo json_encode($response);
        exit();
    }
    $check_email->close();
    
    
    $check_documento = $conn->prepare("SELECT id FROM usuarios WHERE documento = ?");
    $check_documento->bind_param("s", $documento);
    $check_documento->execute();
    $check_documento->store_result();
    
    if ($check_documento->num_rows > 0) {
        $response['success'] = false;
        $response['message'] = "El número de documento ya está registrado";
        $check_documento->close();
        echo json_encode($response);
        exit();
    }
    $check_documento->close();
    
    
    $password_hash = password_hash($password, PASSWORD_DEFAULT);
    
    
    $stmt = $conn->prepare("INSERT INTO usuarios (nombre, documento, email, fecha_nacimiento, password) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $nombre, $documento, $email, $fecha_nacimiento, $password_hash);
    
    if ($stmt->execute()) {
        $response['success'] = true;
        $response['message'] = "Usuario registrado correctamente";
        $response['user_id'] = $stmt->insert_id;
    } else {
        $response['success'] = false;
        $response['message'] = "Error al registrar el usuario: " . $stmt->error;
    }
    
    $stmt->close();
} else {
    $response['success'] = false;
    $response['message'] = "Método no permitido";
}

$conn->close();
echo json_encode($response);
?>