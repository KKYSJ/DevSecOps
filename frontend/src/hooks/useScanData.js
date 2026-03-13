import { useEffect, useState } from "react";
import { getScans } from "../services/scanApi";

export default function useScanData() {
  const [data, setData] = useState([]);
  useEffect(() => { getScans().then(setData).catch(() => setData([])); }, []);
  return data;
}
