# Comandos de Ejecución y Publicación

## 1. Ejecutar la aplicación en desarrollo
```powershell
cd "C:\Users\Administrator\Documents\GitHub\Centro de virlogia\Proyecto"
dotnet run --project src\CentroCiberseguridad.Web

```

## 2. Generar versión pública autocontenida (`win-x64`) y empaquetar en `.ZIP`
```powershell
$proj = "C:\Users\Administrator\Documents\GitHub\Centro de virlogia\Proyecto\src\CentroCiberseguridad.Web\CentroCiberseguridad.Web.csproj"
$outDir = "C:\Users\Administrator\Documents\GitHub\Centro de virlogia\Proyecto\publicado"
$zipPath = "C:\Users\Administrator\Documents\GitHub\Centro de virlogia\Proyecto\CentroCiberseguridad_win-x64.zip"

dotnet publish $proj -c Release -r win-x64 --self-contained true -o $outDir
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
7z a -tzip $zipPath "$outDir\*"

```
