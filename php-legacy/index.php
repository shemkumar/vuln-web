<?php
// INTENTIONALLY VULNERABLE: for SAST/DevSecOps scanner validation only.
ini_set('display_errors', 1); // A05
$db_password = 'Password123!'; // fake hardcoded secret
$conn = mysqli_connect('localhost', 'root', $db_password, 'vulnapp');

if ($_GET['action'] === 'search') {
    $q = $_GET['q'];
    $sql = "SELECT id, title FROM posts WHERE title LIKE '%$q%'"; // A03 SQLi
    echo "<h1>Search: $q</h1>"; // A03 reflected XSS
    $result = mysqli_query($conn, $sql);
    while ($row = mysqli_fetch_assoc($result)) {
        echo '<div>' . $row['title'] . '</div>'; // stored XSS if title contains HTML
    }
}

if ($_GET['action'] === 'include') {
    include($_GET['page']); // A01/A03 local/remote file inclusion pattern
}

if ($_GET['action'] === 'cmd') {
    system('ls ' . $_GET['dir']); // A03 command injection
}

if ($_GET['action'] === 'upload') {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']); // unrestricted upload
    echo 'uploaded';
}

if ($_GET['action'] === 'xml') {
    $xml = simplexml_load_string(file_get_contents('php://input'), 'SimpleXMLElement', LIBXML_NOENT); // XXE pattern
    echo $xml->asXML();
}
?>
