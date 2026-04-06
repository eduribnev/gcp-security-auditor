from google.cloud import storage

def audit_gcp_buckets():
    # Inicializa o cliente do Google Cloud Storage
    storage_client = storage.Client()
    buckets = list(storage_client.list_buckets())

    print(f"--- Iniciando Auditoria de Segurança em {len(buckets)} Buckets ---")

    for bucket in buckets:
        # Obtém a política de acesso (IAM) do bucket
        policy = bucket.get_iam_policy(requested_policy_version=3)
        is_public = False

        # Verifica se 'allUsers' ou 'allAuthenticatedUsers' têm acesso
        for binding in policy.bindings:
            if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                is_public = True
                break

        if is_public:
            print(f"[ALERTA CRÍTICO] Bucket EXPOSTO: {bucket.name}")
        else:
            print(f"[OK] Bucket Seguro: {bucket.name}")

if __name__ == "__main__":
    audit_gcp_buckets()