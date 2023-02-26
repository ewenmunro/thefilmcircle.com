import Link from "next/link";
import Image from "next/image";
import { useContext } from "react";
import { UserContext } from "../libraries/context";

// Top NavBar
export default function NavBar() {
  const { user, username } = useContext(UserContext);

  return (
    <nav className="navbar">
      <ul>
        <li>
          <Link href="/">
            <Image
              src="/../public/the_film_circle_logo.png"
              alt="The Film Circle logo"
              width={30}
              height={30}
            />
          </Link>
        </li>

        {/* user is signed-in and has username */}
        {username && (
          <>
            <li>
              <Link href="/about">
                <button className="btn-white">About</button>
              </Link>
            </li>
            <li className="push-left">
              <Link href="/admin">
                <button className="btn-blue">My Job Posts</button>
              </Link>
            </li>
            <li>
              <Link href={`/${username}`}>
                <img src={user?.photoURL} />
              </Link>
            </li>
          </>
        )}

        {/* user is not signed-in and has not created username */}
        {!username && (
          <>
            <li className="push-left">
              <Link href="/about">
                <button className="btn-white">About</button>
              </Link>
            </li>
            <li>
              <Link href="/enter">
                <button className="btn-blue">Sign In</button>
              </Link>
            </li>
          </>
        )}
      </ul>
    </nav>
  );
}
