import { describe, expect, test } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { render, screen } from '@testing-library/react'
import App from './App'

describe('App routes', () => {
  test('renders landing page headline', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>,
    )

    expect(
      screen.getByRole('heading', {
        name: /protect tool-enabled ai workflows/i,
      }),
    ).toBeTruthy()
  })
})
