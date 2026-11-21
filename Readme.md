# NODO-04 — Centro de Ciberseguridad

Abre una terminal en la carpeta raíz del proyecto (`Proyecto`).

## Ejecutar / Depurar

```powershell
dotnet run --project src\CentroCiberseguridad.Web
```

Luego abre en tu navegador:
- Local: `http://localhost:5000`
- Red LAN: `http://<tu-IP>:5000`

## Ejecutar pruebas

```powershell
dotnet test -c Release
```

## Publicar (versión autocontenida `win-x64`)

Se generará dentro de la carpeta `Proyecto\publicado`:

```powershell
dotnet publish "src\CentroCiberseguridad.Web\CentroCiberseguridad.Web.csproj" -c Release -r win-x64 --self-contained true -o "publicado"
```

Para ejecutarlo en otra PC con Windows (sin instalar `.NET` ni `SQLite`), copia la carpeta `publicado`, haz doble clic en `CentroCiberseguridad.Web.exe` y abre `http://localhost:5000` en el navegador.
