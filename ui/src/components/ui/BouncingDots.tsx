export function BouncingDots() {
  return (
    <span className="inline-flex items-end gap-[1px]">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="inline-block animate-bounce-dot text-primary"
          style={{ animationDelay: `${i * 150}ms` }}
        >
          .
        </span>
      ))}
    </span>
  );
}
