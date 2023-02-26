import styles from "../../styles/Admin.module.css";
import { firestore, auth, serverTimestamp } from "../../libraries/firebase";

import AuthCheck from "../../components/AuthCheck";
import ImageUploader from "../../components/ImageUploader";

import { useState } from "react";
import { useRouter } from "next/router";
import { useDocumentData } from "react-firebase-hooks/firestore";
import { ReactMarkdown } from "react-markdown/lib/react-markdown";
import { useForm } from "react-hook-form";

import Link from "next/link";
import toast from "react-hot-toast";

export default function AdminEditPage({}) {
  return (
    <AuthCheck>
      <PostManager />
    </AuthCheck>
  );
}

function PostManager() {
  const [preview, setPreview] = useState(false);

  const router = useRouter();
  const { slug } = router.query;

  const postRef = firestore
    .collection("users")
    .doc(auth.currentUser.uid)
    .collection("posts")
    .doc(slug);
  const [post] = useDocumentData(postRef);

  return (
    <main className={styles.container}>
      {post && (
        <>
          <section>
            <h1>{post.title}</h1>
            <p>ID: {post.slug}</p>

            <PostForm
              postRef={postRef}
              defaultValues={post}
              preview={preview}
            />
          </section>
          <aside>
            <h3 className="full-width">Tools</h3>
            <button className="full-width" onClick={() => setPreview(!preview)}>
              {preview ? "Edit" : "Preview"}
            </button>
            <Link href={`/${post.username}/${post.slug}`}>
              <button className="btn-blue full-width">Live view</button>
            </Link>
            <DeletePostButton postRef={postRef} />
          </aside>
        </>
      )}
    </main>
  );
}

function PostForm({ defaultValues, postRef, preview }) {
  const { register, handleSubmit, reset, watch, formState, errors } = useForm({
    defaultValues,
    mode: "onChange",
  });

  const { isValid, isDirty } = formState;

  const updatePost = async ({ content, published }) => {
    await postRef.update({
      content,
      published,
      updatedAt: serverTimestamp(),
    });

    reset({ content, published });

    toast.success("Job Post Updated Successfully!");
  };

  return (
    <form onSubmit={handleSubmit(updatePost)}>
      {preview && (
        <div className="card">
          <ReactMarkdown>{watch("content")}</ReactMarkdown>
        </div>
      )}

      <div className={preview ? styles.hidden : styles.controls}>
        <ImageUploader />
        <textarea
          name="content"
          {...register("content", {
            minLength: { value: 10, message: "content is too short" },
            required: { value: true, message: "content is required" },
          })}
        ></textarea>

        {errors?.content && (
          <p className="text-danger">{errors.content.message}</p>
        )}

        <fieldset>
          <input
            className={styles.checkbox}
            type="checkbox"
            {...register("published", { required: true })}
          />
          <label>Published</label>
        </fieldset>
        <button
          type="submit"
          className="btn-green"
          disabled={!isDirty || !isValid}
        >
          Update Job Post
        </button>
      </div>
    </form>
  );
}

function DeletePostButton({ postRef }) {
  const router = useRouter();

  const deletePost = async () => {
    const doIt = confirm("Sure you want to delete this job post?");
    if (doIt) {
      await postRef.delete();
      router.push("/admin");
      toast("Job Post Deleted! ", { icon: "🗑️" });
    }
  };

  return (
    <button className="btn-red full-width" onClick={deletePost}>
      Delete
    </button>
  );
}
