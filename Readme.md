# NODO-04 — Centro de Ciberseguridad

## Requisitos (Windows)

- **.NET 10 SDK** (necesario solo para ejecutar o compilar desde código fuente):
  ```powershell
  winget install Microsoft.DotNet.SDK.10
  ```
  O descárgalo desde: https://dotnet.microsoft.com/download/dotnet/10.0

  Verifica la instalación en PowerShell:
  ```powershell
  dotnet --version
  ```
- **SQLite:** **No requiere instalación** en Windows. Ya viene embebido mediante `Microsoft.Data.Sqlite` y el archivo `ciberseguridad.db` se crea automáticamente al iniciar la aplicación.

---

Abre una terminal en la carpeta raíz del proyecto (`Proyecto`).

## Ejecutar / Depurar

```powershell
dotnet run --project src\CentroCiberseguridad.Web
```

Luego abre en tu navegador:
- Local: `http://localhost:5004`
- Red LAN: `http://<tu-IP>:5004`

## Ejecutar pruebas

```powershell
dotnet test -c Release
```

## Publicar (versión autocontenida `win-x64`)

Se generará dentro de la carpeta `Proyecto\Centro virologia V`:

```powershell
dotnet publish "src\CentroCiberseguridad.Web\CentroCiberseguridad.Web.csproj" -c Release -r win-x64 --self-contained true -o "Centro virologia V2.0"
```

Para ejecutarlo en otra PC con Windows (sin instalar `.NET` ni `SQLite`), copia la carpeta `publicado`, haz doble clic en `CentroCiberseguridad.Web.exe` y abre `http://localhost:5000` en el navegador.
