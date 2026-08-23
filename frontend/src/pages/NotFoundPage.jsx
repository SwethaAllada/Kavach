import { Link } from 'react-router-dom'

export default function NotFoundPage() {
  return (
    <div className="content">
      <div className="notfound">
        <div className="code">404</div>
        <h1>Page not found</h1>
        <Link to="/">Go back home →</Link>
      </div>
    </div>
  )
}
