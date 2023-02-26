import "../styles/globals.css";
import NavBar from "../components/NavBar";
import Tab from "../components/Tab";
import Footer from "../components/Footer";
import { Toaster } from "react-hot-toast";
import { UserContext } from "../libraries/context";
import { useUserData } from "../libraries/hooks";

export default function App({ Component, pageProps }) {
  const userData = useUserData();

  return (
    <UserContext.Provider value={userData}>
      <Tab />
      <NavBar />
      <Component {...pageProps} />
      <Toaster />
      <div className="extra-space"></div>
      <Footer />
    </UserContext.Provider>
  );
}
