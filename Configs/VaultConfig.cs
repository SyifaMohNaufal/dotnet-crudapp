using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

using VaultSharp;
using VaultSharp.V1;
using VaultSharp.V1.AuthMethods.AppRole;
using VaultSharp.V1.SecretsEngines;


public class VaultConfig
{
    private readonly string _vaultAddress;
    private readonly string _vaultNamespace;
    private readonly string _vaultMount;
    private readonly string _vaultSecret;
    private readonly IVaultClient _vaultClient;

    public VaultConfig(IConfiguration configuration)
    {
        var vaultConfig = configuration.GetSection("Vault");

        _vaultAddress = vaultConfig["Address"] ?? throw new ArgumentNullException("Vault:Address");
        _vaultNamespace = vaultConfig["Namespace"] ?? "";
        _vaultMount = vaultConfig["MountPoint"] ?? throw new ArgumentNullException("Vault:MountPoint");
        _vaultSecret = vaultConfig["SecretPath"] ?? throw new ArgumentNullException("Vault:SecretPath");

        var roleId = vaultConfig["RoleId"];
        var secretId = vaultConfig["SecretId"];

        if (string.IsNullOrEmpty(roleId) || string.IsNullOrEmpty(secretId))
            throw new Exception("AppRoleRoleId and AppRoleSecretId must be provided in configuration.");

        var appRoleAuthMethod = new AppRoleAuthMethodInfo(roleId, secretId);

        var vaultClientSettings = new VaultClientSettings(_vaultAddress, appRoleAuthMethod)
        {
            Namespace = _vaultNamespace
        };

        _vaultClient = new VaultClient(vaultClientSettings);

        try
        {
            // Validate token to ensure successful auth
            var self = _vaultClient.V1.Auth.Token.LookupSelfAsync().Result;
            Console.WriteLine("Vault authentication with AppRole succeeded.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Vault authentication failed: " + ex.Message);
            throw;
        }
    }

    public async Task<string> GetSecret(string mountPoint, string secretPath, string key)
    {
        try
        {
            var secret = await _vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: secretPath, mountPoint: mountPoint);

            if (!secret.Data.Data.TryGetValue(key, out var value) || value is null)
                throw new Exception($"Key '{key}' not found in Vault secret at path '{mountPoint}/{secretPath}'.");

            Console.WriteLine($"Successfully retrieved key '{key}' from '{mountPoint}/{secretPath}'.");
            return value.ToString()!;
        }
        catch (Exception ex)
        {
            Console.WriteLine($" Error in GetSecret('{secretPath}', '{key}'): {ex.Message}");
            throw;
        }
    }

    public async Task<string> GetSqlConnectionStringFromSecrets()
    {
        var host = await GetSecret(_vaultMount, _vaultSecret, "Server");
        var user = await GetSecret(_vaultMount, _vaultSecret, "id");
        var pass = await GetSecret(_vaultMount, _vaultSecret, "pwd");
        var db = await GetSecret(_vaultMount, _vaultSecret, "Database");


        Console.WriteLine("SQL connection string successfully built from Vault secrets.");
        return $"Server={host};Database={db};User Id={user};Password={pass};TrustServerCertificate=True;";
    }
}
