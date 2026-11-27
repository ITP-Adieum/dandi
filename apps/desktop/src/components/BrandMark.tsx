interface BrandMarkProps {
  size?: number;
  className?: string;
}

export function BrandMark({ size = 24, className }: BrandMarkProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1024 1024"
      width={size}
      height={size}
      fill="none"
      className={className}
      aria-hidden="true"
    >
      <rect x="48" y="48" width="928" height="928" rx="220" fill="#1D2129" />
      <rect
        x="58"
        y="58"
        width="908"
        height="908"
        rx="210"
        stroke="#FFFFFF"
        strokeOpacity="0.1"
        strokeWidth="12"
      />
      <path
        d="M276 232H516C666 232 764 334 764 512C764 690 666 792 516 792H276C256 792 240 776 240 756V268C240 248 256 232 276 232Z"
        fill="#F5F3EE"
      />
      <path d="M516 232C666 232 764 334 764 512H516V232Z" fill="#D5CFC3" />
      <path
        d="M388 364H504C582 364 624 418 624 512C624 606 582 660 504 660H388V364Z"
        fill="#1D2129"
      />
      <rect x="572" y="454" width="212" height="116" rx="58" fill="#E05532" />
      <circle cx="726" cy="512" r="24" fill="#FAF8F3" />
    </svg>
  );
}
