using VaultSharp;
using VaultSharp.V1;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using Microsoft.Extensions.Configuration;

public class VaultConfig
{
    private readonly string _vaultAddress;
    private readonly string _vaultNamespace;
    private readonly string _vaultMount;
    private readonly string _vaultSecret;
    private readonly string _token;
    private readonly IVaultClient _vaultClient;

    public VaultConfig(IConfiguration configuration)
    {
        var vaultConfig = configuration.GetSection("Vault");

        _vaultAddress = vaultConfig["Address"] ?? throw new ArgumentNullException("Vault:Address");
        _vaultNamespace = vaultConfig["Namespace"] ?? "";
        _vaultMount = vaultConfig["MountPoint"] ?? "";
        _vaultSecret = vaultConfig["SecretPAth"] ?? "";

        var tokenPath = vaultConfig["TokenPath"] ?? "./vault-token";
        _token = File.ReadAllText(tokenPath).Trim();

        IAuthMethodInfo authMethod = new TokenAuthMethodInfo(_token);
        var vaultClientSettings = new VaultClientSettings(_vaultAddress, authMethod)
        {
            Namespace = _vaultNamespace
        };
        _vaultClient = new VaultClient(vaultClientSettings);
    }

    public async Task<string> GetSecret(string mountPoint, string secretPath, string key)
    {
        try
        {
            var secret = await _vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: secretPath, mountPoint: mountPoint);

            if (!secret.Data.Data.TryGetValue(key, out var value) || value is null)
                throw new Exception($"Key '{key}' not found in Vault secret at path '{mountPoint}/{secretPath}'.");

            return value.ToString()!;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error in GetSecret('{secretPath}', '{key}'): {ex.Message}");
            throw;
        }
    }

    public async Task<string> GetSqlConnectionStringFromSecrets()
    {
        var host = await GetSecret(_vaultMount, _vaultSecret, "Server");
        var user = await GetSecret(_vaultMount, _vaultSecret, "id");
        var pass = await GetSecret(_vaultMount, _vaultSecret, "pwd");
        var db = await GetSecret(_vaultMount, _vaultSecret, "Database");

        return $"Server={host};Database={db};User Id={user};Password={pass};TrustServerCertificate=True;";
    }


}
