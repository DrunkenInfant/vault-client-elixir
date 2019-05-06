defmodule Vault.Pki.CertificateIssuer do
  use GenServer
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, opts)
  end

  def init(opts) do
    dest = Keyword.get(opts, :dest)
    vault = Keyword.fetch!(opts, :vault)
    pki_path = Keyword.fetch!(opts, :pki_path)
    pki_role = Keyword.fetch!(opts, :pki_role)

    expire_margin = Keyword.get(opts, :expire_margin, 60)
    min_reissue_time = Keyword.get(opts, :min_reissue_time, 60)
    retry_interval = Keyword.get(opts, :retry_interval, 20)

    common_name = Keyword.fetch!(opts, :common_name)
    issue_opts = opts
                 |> Keyword.take([:ttl])
                 |> Enum.into(%{})
                 |> Map.merge(%{common_name: common_name})

    send(self(), :issue_new)

    {:ok, %{
      vault: vault,
      pki_path: pki_path,
      pki_role: pki_role,
      issue_opts: issue_opts,
      dest: dest,
      expire_margin: expire_margin,
      min_reissue_time: min_reissue_time,
      retry_interval: retry_interval
    }}
  end

  def issue_new(pid), do: Process.send_after(pid, :issue_new, 0)

  def handle_info(:issue_new, %{
    expire_margin: expire_margin,
    min_reissue_time: min_reissue_time,
    retry_interval: retry_interval,
    dest: dest
  } = state) do
    wait_time =
      case get_certificates(state) do
        {:ok, %{key: key, certificate: cert, chain: chain, expires_at: expires_at}} ->
          send_certificates(dest, key, cert, chain)
          valid_duration = Timex.diff(expires_at, Timex.now(), :seconds)
          max(min_reissue_time, (valid_duration - expire_margin))
        err ->
          Logger.error("Issue certificate error: #{inspect err}")
          retry_interval
      end

    Logger.debug("Issue new certificate in: #{wait_time}s")
    Process.send_after(self(), :issue_new, wait_time * 1000)

    {:noreply, state}
  end

  defp get_certificates(%{vault: vault, pki_path: path, pki_role: role, issue_opts: issue_opts}) do
    case Vault.Http.post(vault, "/#{path}/issue/#{role}", issue_opts) do
      {:ok, %{"data" => %{"private_key" => key, "certificate" => cert} = data}} ->
        chain = Map.get(data, "ca_chain", Map.get(data, "issuing_ca"))
        [%{valid_to: valid_to}] = parse_pem_string(cert)
        {:ok, %{key: key, certificate: cert, chain: chain, expires_at: valid_to}}
      e -> e
    end
  end

  defp send_certificates(dest, key, cert, chain) do
    jwk = key
      |> JOSE.JWK.from_pem()
      |> JOSE.JWK.to_map()
      |> (fn {_, jwk} -> jwk end).()
      |> Map.merge(%{"x5c" => get_x5c(cert, chain), "alg" => "RS256"})

    Process.send_after(dest, {:write, jwk}, 0)
  end

  defp get_x5c(cert, chain) do
    "#{cert}#{chain}"
      |> String.replace("\n", "")
      |> (&Regex.scan(~r/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/, &1)).()
      |> Enum.map(fn [_, b64] -> b64 end)
  end

  defp parse_pem_string(pem_string) do
    pem_string
      |> :public_key.pem_decode()
      |> Enum.map(&parse_pem/1)
  end

  defp parse_pem({:Certificate, pem, _}) do
    {:Certificate, {_, _, _, _, _, {:Validity, _from, {:utcTime, valid_to_s}}, _, _, _, _, _}, _, _} = :public_key.pkix_decode_cert(pem, :plain)
    valid_to = Timex.parse!(to_string(valid_to_s), "{ASN1:UTCtime}")
    %{valid_to: valid_to}
  end
  defp parse_pem(_), do: %{}
end
