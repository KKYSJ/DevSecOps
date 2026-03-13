import api from "./api";
export const getIsms = async () => (await api.get("/isms")).data;
