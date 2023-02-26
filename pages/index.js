import Head from "next/head";
import Image from "next/image";
import { Inter } from "@next/font/google";
import styles from "../styles/Home.module.css";

const inter = Inter({ subsets: ["latin"] });

import PostFeed from "../components/PostFeed";
import Loader from "../components/Loader";
import Metatags from "../components/Metatags";
import { firestore, fromMillis, postToJSON } from "../libraries/firebase";

import { useState } from "react";

// Max job posts per page
const LIMIT = 10;

export async function getServerSideProps(context) {
  const postsQuery = firestore
    .collectionGroup("posts")
    .where("published", "==", true)
    .orderBy("createdAt", "desc")
    .limit(LIMIT);

  const posts = (await postsQuery.get()).docs.map(postToJSON);

  return {
    props: { posts },
  };
}

export default function Home(props) {
  const [posts, setPosts] = useState(props.posts);
  const [loading, setLoading] = useState(false);

  const [postsEnd, setPostsEnd] = useState(false);

  const getMorePosts = async () => {
    setLoading(true);
    const last = posts[posts.length - 1];

    const cursor =
      typeof last?.createdAt === "number"
        ? fromMillis(last?.createdAt)
        : last?.createdAt;

    const query = firestore
      .collectionGroup("posts")
      .where("published", "==", true)
      .orderBy("createdAt", "desc")
      // .startAfter(cursor)
      .limit(LIMIT);

    const newPosts = (await query.get()).docs.map((doc) => doc.data());

    setPosts(posts.concat(newPosts));
    setLoading(false);

    if (newPosts.length < LIMIT) {
      setPostsEnd(true);
    }
  };

  return (
    <main>
      <Metatags
        title="The Film Circle"
        description="Inspire | Create | Share"
      />

      <h1 className="header">The Film Circle</h1>

      <PostFeed posts={posts} />

      {!loading && !postsEnd && (
        <div className="box-center btn-container">
          <button onClick={getMorePosts}>Load More</button>
        </div>
      )}
      <div className="box-center btn-container">
        <Loader show={loading} />
        {postsEnd && "No more job posts!"}
      </div>
    </main>
  );
}
