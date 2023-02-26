import Metatags from "../components/Metatags";

export default function About() {
  return (
    <div className="box-center">
      <>
        <Metatags title="About" description="About The Film Circle" />
        <h1>
          About <i>The Film Circle</i>
        </h1>
        <div className="about-text-container">
          <p>
            <i>The Film Circle</i> was founded in 2023, is based in Sydney
            Australia, and was designed to help solve the problems that actors
            and filmmakers face in creating and sharing their films.
          </p>
          <p>
            Currently, <i>The Film Circle</i> acts as a platform to help
            filmmakers in the Sydney film industry find the people they need to
            create and share their film projects. Users can sign up for free and
            post a job on the platform that details who they're looking for and
            share that job post elsewhere to enable them to find that person.
            Because of the way this platform is designed, the SEO makes it
            possible for people outside of the platform to find the job post and
            apply.
          </p>
          <p>
            <i>The Film Circle</i> intends to add features to the platform to
            make it easier for actors and filmmakers to connect with each other.
          </p>
          <p>
            <i>The Film Circle</i> is also developing other products and
            services for actors and filmmakers to help them solve the problems
            that they are facing in the film industry and is actively seeking to
            understand these problems in order to provide solutions for them.
          </p>
          <p>
            If you'd like to suggest a problem for <i>The Film Circle</i> to
            solve, you can send your suggestion via my website:{" "}
            <a
              href="https://ewenmunro.com/contact"
              target="_blank"
              rel="noopener noreferrer"
            >
              ewenmunro.com/contact
            </a>
          </p>
        </div>
      </>
    </div>
  );
}
