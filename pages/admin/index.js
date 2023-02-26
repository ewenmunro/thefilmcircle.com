import styles from "../../styles/Admin.module.css";
import Link from "next/link";

import PostFeed from "../../components/PostFeed";
import AuthCheck from "../../components/AuthCheck";
import Metatags from "../../components/Metatags";
import { UserContext } from "../../libraries/context";
import { firestore, auth, serverTimestamp } from "../../libraries/firebase";

import { useRouter } from "next/router";
import { useContext, useState } from "react";

import { useCollection } from "react-firebase-hooks/firestore";
import kebabCase from "lodash.kebabcase";
import toast from "react-hot-toast";

export default function AdminPostPage({}) {
  return (
    <main>
      <AuthCheck>
        <Metatags
          title="My Job Posts"
          description="My jobs posted to The Film Circle"
        />
        <CreateNewPost />
        <PostList />
      </AuthCheck>
    </main>
  );
}

function PostList() {
  const ref = firestore
    .collection("users")
    .doc(auth.currentUser.uid)
    .collection("posts");
  const query = ref.orderBy("createdAt");
  const [querySnapshot] = useCollection(query);

  const posts = querySnapshot?.docs.map((doc) => doc.data());

  return (
    <>
      {posts && posts.length > 0 ? <h1>My Job Posts</h1> : null}
      <PostFeed posts={posts} admin />
    </>
  );
}

function CreateNewPost() {
  const router = useRouter();
  const { username } = useContext(UserContext);
  const [title, setTitle] = useState("");

  const slug = encodeURI(kebabCase(title));
  const isValid = title.length > 3;

  const createPost = async (e) => {
    e.preventDefault();
    const uid = auth.currentUser.uid;
    const ref = firestore
      .collection("users")
      .doc(uid)
      .collection("posts")
      .doc(slug);

    const data = {
      title,
      slug,
      uid,
      username,
      published: false,
      content: "Write your job post here",
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      heartCount: 0,
    };

    await ref.set(data);

    toast.success("Job Post Created!");

    router.push(`/admin/${slug}`);
  };

  return (
    <>
      <h1>Create New Job Post</h1>
      <p>
        For consistency and stronger SEO results, write your new job post title
        in following way:
      </p>
      <p>
        <strong>
          DD/MM/YYYY: Location (e.g. Sydney CBD, Australia), state whether
          'paid' or 'unpaid', description of what you are looking for (e.g. 1x
          female actor, 20-27, Caucasian, blonde hair, blue eyes)
        </strong>
      </p>
      <p>
        If unsure, look to the <Link href="/">home page</Link> for reference.
      </p>
      <form onSubmit={createPost}>
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Write new job post title here"
          className={styles.input}
        />
        <p>
          <strong>Slug:</strong> {slug}
        </p>
        <button type="submit" disabled={!isValid} className="btn-green">
          Create New Job Post
        </button>
      </form>
    </>
  );
}
