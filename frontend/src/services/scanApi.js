import api from "./api";
export async function getScans() { const response = await api.get("/scans"); return response.data; }
