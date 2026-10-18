<#
.SYNOPSIS
    Capture a single application window to a PNG.

.DESCRIPTION
    Used to verify the GUI actually renders. Two deliberate restrictions:

    * Only a named process's main window can be captured -- never the desktop.
      A full-screen grab would pick up whatever else the user happens to have
      open, which is not this tool's business.
    * The capture uses PrintWindow rather than a screen grab, so it works even
      when the window is behind others and never steals the user's focus.

.PARAMETER OutFile
    Destination PNG path.

.PARAMETER ProcessName
    Process whose main window to capture, without the .exe suffix.

.EXAMPLE
    powershell -File scripts\screenshot.ps1 -ProcessName pythonw -OutFile shot.png
#>
param(
    [Parameter(Mandatory = $true)][string]$OutFile,
    [Parameter(Mandatory = $true)][string]$ProcessName
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

# -ReferencedAssemblies is required: loading System.Drawing for PowerShell does
# not make it available to the C# compiler Add-Type invokes.
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Drawing;
using System.Runtime.InteropServices;

public static class WindowCapture {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("dwmapi.dll")] static extern int DwmGetWindowAttribute(
        IntPtr h, int attr, out RECT r, int size);

    // PW_RENDERFULLCONTENT: required for windows that render via DirectComposition
    // (which includes most modern control toolkits); plain PrintWindow returns
    // a blank bitmap for them.
    const uint PW_RENDERFULLCONTENT = 0x00000002;
    // DWMWA_EXTENDED_FRAME_BOUNDS: the real visible bounds, excluding the
    // invisible resize border GetWindowRect includes on Windows 10+.
    const int DWMWA_EXTENDED_FRAME_BOUNDS = 9;

    public static string Capture(IntPtr hwnd, string path) {
        RECT r;
        int hr = DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, out r,
                                       Marshal.SizeOf(typeof(RECT)));
        if (hr != 0 || r.Right <= r.Left) {
            if (!GetWindowRect(hwnd, out r)) throw new Exception("GetWindowRect failed");
        }
        int w = r.Right - r.Left;
        int h = r.Bottom - r.Top;
        if (w <= 0 || h <= 0) throw new Exception("window has no area");

        using (var bmp = new Bitmap(w, h))
        using (var g = Graphics.FromImage(bmp)) {
            IntPtr hdc = g.GetHdc();
            bool ok = PrintWindow(hwnd, hdc, PW_RENDERFULLCONTENT);
            g.ReleaseHdc(hdc);
            if (!ok) throw new Exception("PrintWindow failed");
            bmp.Save(path, System.Drawing.Imaging.ImageFormat.Png);
        }
        return w + "x" + h;
    }

    public static bool Visible(IntPtr h) { return IsWindowVisible(h); }
}
'@

$proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowHandle -ne 0 -and [WindowCapture]::Visible($_.MainWindowHandle) } |
    Select-Object -First 1
if (-not $proc) { throw "no visible window found for process '$ProcessName'" }

$dir = Split-Path -Parent $OutFile
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

$size = [WindowCapture]::Capture($proc.MainWindowHandle, (Resolve-Path -LiteralPath $dir).Path + '\' + (Split-Path -Leaf $OutFile))
Write-Host "saved $OutFile ($size) from $($proc.ProcessName) pid $($proc.Id)"
