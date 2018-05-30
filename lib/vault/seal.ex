defmodule Vault.Seal do
  def unseal(vault, key) do
    case Vault.Http.put(vault, "/sys/unseal", %{"key" => key}) do
      {:ok, %{"sealed" => false}} -> {:ok, %{"status" => "Unsealed", "sealed" => false}}
      {:ok, %{"t" => t, "n" => n, "progress" => p}} -> {:ok, %{"sealed" => true, "status" => "#{p}/#{t} keys provided. #{n} keys total."}}
      {_, err} -> {:error, err}
    end
  end
end
