defmodule Vault.Conn do
  @enforce_keys [:host]
  defstruct [:host, :ca_fingerprint, :token]

  @type t :: %__MODULE__{
          host: String.t(),
          token: String.t(),
          ca_fingerprint: {atom, binary}
        }

  def init(opts) do
    case validate_opts(opts) do
      :ok -> {:ok, struct(__MODULE__, opts)}
      err -> err
    end
  end

  defp validate_opts(opts) do
    with :ok <- validate_opts_host(Keyword.get(opts, :host, "")),
         :ok <- validate_opts_fingerprint(Keyword.get(opts, :ca_fingerprint)) do
      :ok
    else
      err -> err
    end
  end

  defp validate_opts_host("https://" <> _), do: :ok
  defp validate_opts_host("http://" <> _), do: {:error, "Vault URL must be https"}
  defp validate_opts_host(url), do: {:error, "Invalid URL '#{url}'"}

  defp validate_opts_fingerprint(nil), do: :ok
  defp validate_opts_fingerprint({:sha256, hash}) when is_bitstring(hash), do: :ok
  defp validate_opts_fingerprint(f), do: {:error, "Invalid CA fingerprint '#{inspect(f)}'"}
end
