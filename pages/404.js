import Link from "next/link";

export default function Custom404() {
  return (
    <main className="box-center">
      <h1>404 - This page does not exist...</h1>
      <h2>Go to Home Page:</h2>
      <Link href="/">
        <button className="btn-blue btn-container">Home</button>
      </Link>
    </main>
  );
}
