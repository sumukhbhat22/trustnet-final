import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import '@fontsource/jost/300.css';
import '@fontsource/jost/400.css';
import '@fontsource/jost/500.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import "./index.css";
import "./styles/trustnet-theme.css";

createRoot(document.getElementById("root")!).render(<App />);
