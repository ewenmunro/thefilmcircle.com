import styles from "../../styles/Post.module.css";
import PostContent from "../../components/PostContent";
import {
  firestore,
  getUserWithUsername,
  postToJSON,
} from "../../libraries/firebase";
import { useDocumentData } from "react-firebase-hooks/firestore";

import { UserContext } from "../../libraries/context";
import { useContext } from "react";

import Link from "next/link";

export async function getStaticProps({ params }) {
  const { username, slug } = params;
  const userDoc = await getUserWithUsername(username);

  let post;
  let path;

  if (userDoc) {
    const postRef = userDoc.ref.collection("posts").doc(slug);
    post = postToJSON(await postRef.get());

    path = postRef.path;
  }

  return {
    props: { post, path },
    revalidate: 100,
  };
}

export async function getStaticPaths() {
  const snapshot = await firestore.collectionGroup("posts").get();

  const paths = snapshot.docs.map((doc) => {
    const { slug, username } = doc.data();
    return {
      params: { username, slug },
    };
  });

  return {
    paths,
    fallback: "blocking",
  };
}

export default function Post({ post, path }) {
  const postRef = firestore.doc(path);
  const [realtimePost] = useDocumentData(postRef);

  const currentPost = realtimePost || post;

  const { user: currentUser } = useContext(UserContext);

  return (
    <main className={styles.container}>
      <section>
        <PostContent post={currentPost} />
      </section>

      <aside className="card">
        {currentUser?.uid === post.uid && (
          <Link href={`/admin/${post.slug}`}>
            <br /> <br /> <br /> <br />
            <button className="btn-blue">Edit Post</button>
          </Link>
        )}
      </aside>
    </main>
  );
}
