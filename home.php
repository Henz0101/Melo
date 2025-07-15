<?php
require_once("configuration/config.php");
session_start(); // Start the session

// Redirect to login if the user isn't logged in
if (!isset($_SESSION['username'])) {
    header("Location: login.php"); // Redirect the user to the login page
    exit();
}

// Handle like button functionality
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['like_post'])) {
    $postId = intval($_POST['post_id']);
    $userId = $_SESSION['user_id']; // Replace with actual user ID from session.

    try {
        // Check if the user already liked the post
        $checkQuery = $pdo->prepare("SELECT * FROM reactions WHERE user_id = :user_id AND post_id = :post_id");
        $checkQuery->execute(['user_id' => $userId, 'post_id' => $postId]);

        if ($checkQuery->rowCount() > 0) {
            // Unlike if already liked
            $deleteQuery = $pdo->prepare("DELETE FROM reactions WHERE user_id = :user_id AND post_id = :post_id");
            $deleteQuery->execute(['user_id' => $userId, 'post_id' => $postId]);
        } else {
            // Like the post
            $insertQuery = $pdo->prepare("INSERT INTO reactions (user_id, post_id) VALUES (:user_id, :post_id)");
            $insertQuery->execute(['user_id' => $userId, 'post_id' => $postId]);
        }
    } catch (PDOException $e) {
        die("Error handling like: " . $e->getMessage());
    }

    // Refresh the current page without clearing the session
    header("Refresh:0");
    exit();
}

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment_submit'])) {
    $postId = intval($_POST['post_id']);
    $userId = $_SESSION['user_id']; // Get the user ID from session
    $commentContent = htmlspecialchars($_POST['comment_content']); // Comment content

    try {
        // Insert the comment into the database
        $commentQuery = $pdo->prepare("INSERT INTO comments (post_id, user_id, comment_content) VALUES (:post_id, :user_id, :comment_content)");
        $commentQuery->execute(['post_id' => $postId, 'user_id' => $userId, 'comment_content' => $commentContent]);
    } catch (PDOException $e) {
        die("Error handling comment: " . $e->getMessage());
    }

    // Refresh the current page without redirect
    header("Refresh:0");
    exit();
}

// Fetch posts along with the username from the database
try {
    $query = $pdo->prepare(
        "SELECT user_posts.*, users.username 
         FROM user_posts 
         JOIN users ON user_posts.user_id = users.id 
         ORDER BY user_posts.created_at DESC"
    );
    $query->execute();
    $posts = $query->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    die("Error fetching posts: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Home</title>
  <!-- Open Sans Font -->
  <link
    href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600&display=swap"
    rel="stylesheet"
  />
  <!-- Poppins Font -->
  <link
    href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap"
    rel="stylesheet"
  />
  <style>
    /* General Reset */
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    /* Body & Main Font */
    body {
      font-family: 'Open Sans', sans-serif;
      background: #f0f2f5;
      color: #333;
      line-height: 1.6;
    }

    /* Header Section */
    header {
      background: #4267b2;
      color: white;
      padding: 10px 20px;
      text-align: left;
      font-size: 20px;
      font-weight: 600;
    }

    .logo {
      font-weight: 600;
      display: inline-block;
      font-family: 'Poppins', sans-serif;
    }

    /* Search Box */
    .search-box {
      margin: 10px auto;
      max-width: 500px;
      text-align: center;
      display: flex;
      align-items: center;
      gap: 10px; /* Add spacing between the elements */
    }

    .search-box form {
      display: flex;
      flex-grow: 1;
    }

    .search-box input {
      width: calc(100% - 110px); /* Adjusted width for the post button */
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 25px;
      outline: none;
      font-size: 14px;
    }

    .search-box input::placeholder {
      font-family: 'Open Sans', sans-serif;
    }

    .post-btn {
      padding: 10px 20px;
      background-color: #4267b2;
      color: white;
      border: none;
      border-radius: 25px;
      cursor: pointer;
      font-family: 'Open Sans', sans-serif;
      font-size: 14px;
      font-weight: 600;
      text-align: center;
      text-decoration: none;
    }

    .post-btn:hover {
      background-color: #365899;
    }

    .search-error {
      color: red;
      font-size: 14px;
      margin-top: 5px;
    }

    /* Main Section */
    main {
      padding: 10px 20px;
    }

    /* Post Section */
    .post-container {
      max-width: 600px;
      margin: 0 auto;
    }

    .post {
      background: white;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
      padding: 15px;
      margin: 10px 0;
      transition: box-shadow 0.2s ease;
    }

    .post:hover {
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
    }

    /* Post Header */
    .post-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
      font-size: 14px;
      color: #555;
    }

    .user-profile {
      font-weight: 600;
    }

    .post-time {
      color: #777;
      font-size: 12px;
    }

    /* Post Content */
    .post-content {
      font-size: 15px;
      margin-bottom: 10px;
      color: #555;
    }

    /* Divider */
    .post-divider {
      border-bottom: 1px solid #ddd;
      margin: 10px 0;
    }

    /* Like Button */
    .like-btn {
      background-color: transparent;
      border: none;
      padding: 5px;
      cursor: pointer;
      display: flex;
      align-items: center;
    }

    .like-btn img {
      width: 30px; /* Adjust the icon size */
      height: 30px;
    }

    .like-count {
      font-size: 14px;
      color: #555;
      margin-left: 10px; /* Add space between icon and count */
    }

    /* Comment Icon */
    .comment-icon {
      width: 25px;
      height: 25px;
      cursor: pointer;
      margin-left: 10px;
    }

    /* Upward Transition Page */
    .comments-modal {
      position: fixed;
      bottom: -100%;
      left: 0;
      width: 100%;
      height: 60%;
      background: white;
      box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.2);
      transition: bottom 0.3s ease;
      padding: 20px;
      overflow-y: auto;
    }

    .comments-modal.active {
      bottom: 0;
    }

    .comments-modal header {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 10px;
    }

    .comment {
      margin-bottom: 10px;
      border-bottom: 1px solid #ddd;
      padding-bottom: 10px;
    }

    /* Close Button */
    .close-btn {
      background-color: #4267b2;
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 25px;
      cursor: pointer;
      font-weight: 600;
      margin-top: 10px;
    }

    .close-btn:hover {
      background-color: #365899;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo">"Melo"</div>
    <div class="user-greeting">👤 Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</div>
  </header>

  <div class="search-box">
    <form method="POST" action="">
      <input type="text" name="search_user" placeholder="Search for a user..." required />
    </form>
    <a href="create_post.php" class="post-btn">Post</a>
    <?php if (isset($searchError)): ?>
      <div class="search-error"><?php echo htmlspecialchars($searchError); ?></div>
    <?php endif; ?>
  </div>

  <main>
    <div class="post-container">
      <?php if (empty($posts)): ?>
        <div class="post">
          <div class="post-content" style="text-align: center; font-weight: 600; color: #555;">
            No posts available. Be the first to create one!
          </div>
        </div>
      <?php else: ?>
        <?php foreach ($posts as $post): ?>
          <div class="post">
            <div class="post-header">
              <div class="user-profile">👤 <?php echo htmlspecialchars($post['username']); ?></div>
              <div class="post-time">
                <?php
                $createdAt = new DateTime($post['created_at']);
                echo $createdAt->format('F j, Y, g:i a');
                ?>
              </div>
            </div>
            <div class="post-content">
              <strong><?php echo htmlspecialchars($post['title']); ?></strong><br />
              <?php echo nl2br(htmlspecialchars($post['content'])); ?>
            </div>
            <div class="post-divider"></div>

            <form method="POST" action="">
              <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
              <button type="submit" name="like_post" class="like-btn">
                <img src="assets/icons/like_icon.png" alt="Like">
              </button>
              <span class="like-count">
                <?php
                try {
                    $likeCountQuery = $pdo->prepare("SELECT COUNT(*) FROM reactions WHERE post_id = :post_id");
                    $likeCountQuery->execute(['post_id' => $post['id']]);
                    echo $likeCountQuery->fetchColumn();
                } catch (PDOException $e) {
                    echo "0";
                }
                ?>
              </span>
            </form>
            <img src="assets/icons/comment_icon.png" alt="Comments" class="comment-icon" onclick="openComments(<?php echo $post['id']; ?>)">
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>
  </main>

  <div id="commentsModal" class="comments-modal">
    <header>Comments</header>
    <div id="commentsContent"></div>
    <button class="close-btn" onclick="closeComments()">Close</button>
  </div>

  <script>
    function openComments(postId) {
      const modal = document.getElementById('commentsModal');
      modal.classList.add('active');
      fetch(`fetch_comments.php?post_id=${postId}`)
        .then(response => response.text())
        .then(data => {
          document.getElementById('commentsContent').innerHTML = data;
        })
        .catch(error => console.error('Error fetching comments:', error));
    }

    function closeComments() {
      const modal = document.getElementById('commentsModal');
      modal.classList.remove('active');
    }
  </script>
</body>
</html>