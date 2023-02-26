import Head from "next/head";

export default function Metatags({
  title = "The Film Circle",
  description = "Inspire | Create | Share",
  image = "https://thefilmcircle.com/public/the_film_circle_logo.png",
}) {
  return (
    <Head>
      <title>{title}</title>
      <meta name="twitter:title" content={title} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={image} />

      <meta property="og:title" content={title} />
      <meta property="og:description" content={description} />
      <meta property="og:image" content={image} />
    </Head>
  );
}
