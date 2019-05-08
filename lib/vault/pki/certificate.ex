defmodule Vault.Pki.CertificateSet do
  @type t :: %__MODULE__{
          private_key: String.t(),
          certificate: String.t(),
          chain: list(String.t())
        }
  defstruct [:private_key, :certificate, :chain]

  @pem_bounds_pattern ~r/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/

  def new(private_key, certificate, chain) when is_bitstring(chain),
    do: new(
      private_key,
      certificate,
      Regex.scan(@pem_bounds_pattern, chain) |> Enum.map(&List.first/1)
    )

  def new(private_key, certificate, chain) when is_list(chain) do
    %__MODULE__{
      private_key: private_key,
      certificate: certificate,
      chain: chain
    }
  end
end
