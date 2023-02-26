import { getUserWithUsername, postToJSON } from "../../libraries/firebase";
import UserProfile from "../../components/UserProfile";
import PostFeed from "../../components/PostFeed";
import Metatags from "../../components/Metatags";

export async function getServerSideProps({ query }) {
  const { username } = query;

  const userDoc = await getUserWithUsername(username);

  if (!userDoc) {
    return {
      notFound: true,
    };
  }

  let user = null;
  let posts = null;

  if (userDoc) {
    user = userDoc.data();
    const postsQuery = userDoc.ref
      .collection("posts")
      .where("published", "==", true)
      .orderBy("createdAt", "desc")
      .limit(5);

    posts = (await postsQuery.get()).docs.map(postToJSON);
  }

  return {
    props: { user, posts },
  };
}

export default function UserProfilePage({ user, posts }) {
  return (
    <main>
      <Metatags
        title={user.username}
        description={`${user.username}'s profile`}
      />
      <UserProfile user={user} />
      {posts && posts.length > 0 ? (
        <h2 className="box-center">{user.displayName}'s Job Posts:</h2>
      ) : null}
      <PostFeed posts={posts} />
    </main>
  );
}
