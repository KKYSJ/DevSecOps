import api from "./api";
export const getSiem = async () => (await api.get("/siem")).data;
